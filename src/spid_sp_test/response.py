import datetime
import random
import logging
import os
import string

from copy import deepcopy
from jinja2 import (Environment, 
                    Markup, 
                    PackageLoader, 
                    Template, 
                    select_autoescape)
from lxml import etree

from saml2.sigver import CryptoBackendXmlSec1
from spid_sp_test import BASE_DIR, AbstractSpidCheck
from spid_sp_test.authn_request import get_authn_request
from spid_sp_test.idp.settings import SAML2_IDP_CONFIG
from spid_sp_test.responses import settings
from spid_sp_test.utils import del_ns, prettify_xml


logger = logging.getLogger(__name__)


def stupid_rnd_string(N=32):
    return '_' + ''.join(random.choice(string.ascii_lowercase + '_') for _ in range(N))


def get_xmlsec1_bin():
    env_bin = os.environ.get('XMLSEC1_BIN')
    if env_bin:
        return env_bin
    else:
        for i in ("/usr/bin/xmlsec1", "/usr/local/bin/xmlsec1"):
            if os.access(i, os.X_OK):
                return i


class SpidSpResponse(object):
    def __init__(self, conf=None, authnreq_attrs={},attributes={}):
        self.conf = deepcopy(conf or settings.RESPONSE_TESTS['1'])
        self.attributes = attributes
        self.authnreq_attrs = authnreq_attrs
        self.loader = Environment(
                    loader = PackageLoader('responses', 'templates'),
                    autoescape = select_autoescape(['xml'])
        )


    def render_attributes(self, attributes={}):
        # fill attributes
        attr_rendr_list = []
        attrs = attributes or self.attributes or settings.ATTRIBUTES
        
        for k,v in attrs.items():
            template = Template(settings.ATTRIBUTE_TMPL)
            attr_type = settings.ATTRIBUTES_TYPES.get(k, 'string')
            attr_rendr = template.render(name=k, value=v, type=attr_type)
            attr_rendr_list.append(attr_rendr)
        return Markup('\n'.join(attr_rendr_list))


    def render(self, template:str='base.xml', data:dict={}):
        template = self.loader.get_template(template)
        data['Attributes'] = self.render_attributes()
        
        result = template.render(**data)
        logger.debug(f"Rendering response template {template}: {result}")
        return result


    def __str__(self):
        return self.conf


class SpidSpResponseCheck(AbstractSpidCheck):    
    template_base_dir = f'{BASE_DIR}/responses/test/'


    def __init__(self, *args, **kwargs):
        super(SpidSpResponseCheck, self).__init__(*args, **kwargs)
        self.category = 'response'

        self.template_base_dir = kwargs.get('template_base_dir', 
                                            self.template_base_dir)

        self.metadata_etree = kwargs.get('metadata_etree')
        self.authn_request_url = kwargs.get('authn_request_url')
        self.authn_request_data = get_authn_request(self.authn_request_url)
        self.authnreq_etree = etree.fromstring(self.authn_request_data['SAMLRequest_xml'])
        del_ns(self.authnreq_etree)
        self.authnreq_attrs = self.authnreq_etree.xpath("/AuthnRequest")[0].attrib
        self.response_attrs = {
            'ResponseID': stupid_rnd_string(),
            'AuthnRequestID': self.authnreq_attrs['ID'],
            'IssueInstant': self.authnreq_attrs['IssueInstant'],
            'NotOnOrAfter': (datetime.datetime.utcnow() + datetime.timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'AssertionConsumerURL':  self.authnreq_attrs['AssertionConsumerServiceURL'],
            'NameIDNameQualifier': settings.DEFAULT_RESPONSE['NameIDNameQualifier'],
            'NameID': 'that-transient-opaque-value',
            'AssertionID': stupid_rnd_string(),
            'AuthnIstant': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'SessionIndex': stupid_rnd_string()
        }
        self.relay_state = kwargs.get('relay_state')

        self.crypto_backend = CryptoBackendXmlSec1(xmlsec_binary=get_xmlsec1_bin())
        self.private_key_fpath = SAML2_IDP_CONFIG['key_file']


    def sign(self, xmlstr, assertion=True, node_name = '', response=True, key_file=None):
        """
        Sign an XML statement.

        The parameters actually used in this CryptoBackend
        implementation are :

        :param statement: XML as string
        :param node_name: Name of the node to sign
        :param key_file: xmlsec key_spec string(), filename,
            'pkcs11://' URI or PEM data
        :returns: Signed XML as string
        """

        key = key_file or self.private_key_fpath
        signature_node = Template(settings.SIGNATURE_TMPL)

        params = dict(statement = xmlstr, 
              key_file = key, 
        )

        if assertion:
            value = signature_node.render(
                        {'ReferenceURI': f"#{self.response_attrs['AssertionID']}"}
            )
            xmlstr = xmlstr.replace('<!-- Assertion Signature here -->', value)
            params.update(
                {
                    'node_name' : 'urn:oasis:names:tc:SAML:2.0:assertion:Assertion',
                    'node_id' : f'{self.response_attrs["AssertionID"]}',
                    'statement': xmlstr
                }
            )            
            xmlstr = self.crypto_backend.sign_statement(**params)

        if response:
            value = signature_node.render(
                        {'ReferenceURI': f"#{self.response_attrs['ResponseID']}"}
            )
            xmlstr = xmlstr.replace('<!-- Response Signature here -->', value)
            params.update(
                {
                    'node_name' : 'urn:oasis:names:tc:SAML:2.0:protocol:Response',
                    'node_id' : f'{self.response_attrs["ResponseID"]}',
                    'statement': xmlstr
                }
            )
            xmlstr = self.crypto_backend.sign_statement(**params)

        return xmlstr


    def load_test(self, test_name=None, attributes={}):
        return SpidSpResponse(test_name, 
                              authnreq_attrs = self.authnreq_attrs, 
                              attributes = attributes)

    def test_all(self):
        response_obj = self.load_test()
        xmlstr = response_obj.render(data = self.response_attrs) 
        result = self.sign(xmlstr)
        pretty_xml = prettify_xml(result)
        print(pretty_xml.decode())
