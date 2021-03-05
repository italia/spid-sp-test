import logging 

from copy import deepcopy
from jinja2 import (Environment, 
                    Markup, 
                    PackageLoader, 
                    Template, 
                    select_autoescape)
from lxml import etree

from saml2.sigver import CryptoBackendXMLSecurity
from spid_sp_test import BASE_DIR, AbstractSpidCheck
from spid_sp_test.authn_request import get_authn_request
from spid_sp_test.idp.settings import SAML2_IDP_CONFIG
from spid_sp_test.responses import test_config
from spid_sp_test.utils import del_ns, prettify_xml


logger = logging.getLogger(__name__)


class SpidSpResponse(object):
    def __init__(self, conf=None, attributes={}):
        self.conf = deepcopy(conf or test_config.RESPONSE_TESTS['1'])
        self.attributes = attributes
        self.loader = Environment(
                    loader = PackageLoader('responses', 'templates'),
                    autoescape = select_autoescape(['xml'])
        )


    def render_attributes(self, attributes={}):
        # fill attributes
        attr_rendr_list = []
        attrs = attributes or self.attributes or test_config.ATTRIBUTES
        for k,v in attrs.items():
            template = Template(test_config.ATTRIBUTE_TMPL)
            attr_type = test_config.ATTRIBUTES_TYPES.get(k, 'string')
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
        
        self.relay_state = kwargs.get('relay_state')
        
        self.crypto_backend = CryptoBackendXMLSecurity()
        self.private_key_fpath = SAML2_IDP_CONFIG['key_file']


    def sign(self, xmlstr, assertion=True, response=True, key_file=None):
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

        params = dict(statement = xmlstr, 
                      key_file = key, 
                      node_id = 'ID')
        result = xmlstr

        if assertion:
            params['node_name'] = 'urn:oasis:names:tc:SAML:2.0:assertion:Assertion'
            result = self.crypto_backend.sign_statement(**params)
            params['statement'] = result

        if response:
            params['node_name'] = 'urn:oasis:names:tc:SAML:2.0:protocol:Response'
            response_signed = self.crypto_backend.sign_statement(**params)

        return response_signed


    def load_test(self, test_name=None, attributes={}):
        return SpidSpResponse(test_name, attributes)

    def test_all(self):
        response_obj = self.load_test()
        xmlstr = response_obj.render() 
        result = self.sign(xmlstr)
        pretty_xml = prettify_xml(result)
        print(pretty_xml.decode())
