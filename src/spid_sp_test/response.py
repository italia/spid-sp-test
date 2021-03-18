import base64
import datetime
import random
import logging
import os
import string

from copy import deepcopy
from jinja2 import (Environment,
                    Markup,
                    FileSystemLoader,
                    Template,
                    select_autoescape)
from lxml import etree

from saml2.sigver import CryptoBackendXmlSec1, XmlsecError
from spid_sp_test import BASE_DIR, AbstractSpidCheck
from spid_sp_test.authn_request import get_authn_request
from spid_sp_test.idp.settings import SAML2_IDP_CONFIG
from spid_sp_test.responses import settings
from spid_sp_test.utils import del_ns, prettify_xml

from . utils import get_xmlsec1_bin

logger = logging.getLogger(__name__)


def stupid_rnd_string(N=32):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(N))

def saml_rnd_id():
    return (f"_{stupid_rnd_string(8)}"
            f"-{stupid_rnd_string(4)}"
            f"-{stupid_rnd_string(4)}"
            f"-{stupid_rnd_string(4)}"
            f"-{stupid_rnd_string(12)}")


class SpidSpResponse(object):
    def __init__(self,
                 conf=None,
                 response_attrs={},
                 authnreq_attrs={},
                 attributes={},
                 template_path='./templates'):

        try:
            self.conf = deepcopy(
                            settings.RESPONSE_TESTS[conf] or
                            settings.RESPONSE_TESTS['1']
                        )
        except KeyError:
            raise Exception(f'Test {conf} doesn\'t exists')

        self.attributes = attributes
        self.authnreq_attrs = authnreq_attrs

        # overload response args with values taken from test conf
        self.response_attrs = response_attrs
        if self.conf.get('response'):
            for k,v in self.conf['response'].items():
                logger.debug(f'Test {self.conf}: overwriting {k} with {v}')
                self.response_attrs[k] = v

        self.loader = Environment(
                    loader = FileSystemLoader(searchpath=template_path),
                    autoescape = select_autoescape(['xml'])
        )
        self.template_name = self.conf.get('path', 'base.xml')
        self.private_key = self.conf.get('sign_credentials', {}).get('privateKey')


    def render_attributes(self, attributes={}):
        """
            fill values to be released as identity attributes
        """
        attr_rendr_list = []
        attrs = attributes or self.attributes or settings.ATTRIBUTES

        for k,v in attrs.items():
            template = Template(settings.ATTRIBUTE_TMPL)
            attr_type = settings.ATTRIBUTES_TYPES.get(k, 'string')
            attr_rendr = template.render(name=k, value=v, type=attr_type)
            attr_rendr_list.append(attr_rendr)
        return Markup('\n'.join(attr_rendr_list))


    def render(self, data:dict={}):
        template = self.loader.get_template(self.template_name)
        data = data or self.response_attrs
        data['Attributes'] = self.render_attributes()
        result = template.render(**data)
        logger.debug(f"Rendering response template {template}: {result}")
        return result


    def __str__(self):
        return self.conf


class SpidSpResponseCheck(AbstractSpidCheck):
    template_path = f'{BASE_DIR}/responses/templates/'


    def __init__(self, *args, **kwargs):
        super(SpidSpResponseCheck, self).__init__(*args, **kwargs)
        self.category = 'response'

        self.template_path = kwargs.get('template_path',
                                        self.template_path)

        self.metadata_etree = kwargs.get('metadata_etree')
        self.authn_request_url = kwargs.get('authn_request_url')

        self.crypto_backend = CryptoBackendXmlSec1(
            xmlsec_binary=kwargs.get('xmlsec_binary') or get_xmlsec1_bin()
        )
        self.private_key_fpath = SAML2_IDP_CONFIG['key_file']
        self.test_names = kwargs.get('test_names') or settings.RESPONSE_TESTS.keys()
        self.kwargs = kwargs

    def do_authnrequest(self):
        self.authn_request_data = get_authn_request(self.authn_request_url)
        self.authnreq_etree = etree.fromstring(self.authn_request_data['SAMLRequest_xml'])
        del_ns(self.authnreq_etree)

        self.issuer = self.kwargs.get('issuer', SAML2_IDP_CONFIG["entityid"])
        self.authnreq_attrs = self.authnreq_etree.xpath("/AuthnRequest")[0].attrib
        self.authnreq_issuer = self.authnreq_etree.xpath("/AuthnRequest/Issuer")[0].attrib['NameQualifier']
        now = datetime.datetime.utcnow()
        self.response_attrs = {
            'ResponseID': saml_rnd_id(),
            'AuthnRequestID': self.authnreq_attrs['ID'],
            'IssueInstant': self.authnreq_attrs['IssueInstant'],
            'NotOnOrAfter': (now + datetime.timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'AssertionConsumerURL':  self.authnreq_attrs['AssertionConsumerServiceURL'],
            'NameIDNameQualifier': settings.DEFAULT_RESPONSE['NameIDNameQualifier'],
            'NameID': 'that-transient-opaque-value',
            'AssertionID': saml_rnd_id(),
            'AuthnIstant': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'SessionIndex': saml_rnd_id(),
            'Issuer': self.issuer,
            'Audience': self.authnreq_issuer,
            'IssueInstantMillis': now.strftime('%Y-%m-%d %H:%M%S') + ':20.621Z'
        }
        self.relay_state = self.kwargs.get('relay_state')

    def sign(self, xmlstr, assertion=True, response=True, key_file=None):
        """
        Sign an XML statement.
        """
        signature_node = Template(settings.SIGNATURE_TMPL)
        params = dict(
              key_file = key_file or self.private_key_fpath,
        )
        asser_placeholder = '<!-- Assertion Signature here -->'
        if assertion and asser_placeholder in xmlstr:
            value = signature_node.render(
                {'ReferenceURI': f"#{self.response_attrs['AssertionID']}"}
            )
            xmlstr = xmlstr.replace(asser_placeholder, value)
            params.update(
                {
                    'node_name' : 'urn:oasis:names:tc:SAML:2.0:assertion:Assertion',
                    'node_id' : f'{self.response_attrs["AssertionID"]}',
                    'statement': xmlstr
                }
            )
            xmlstr = self.crypto_backend.sign_statement(**params)

        sign_placeholder = '<!-- Response Signature here -->'
        if response and sign_placeholder in xmlstr:
            value = signature_node.render(
                {'ReferenceURI': f"#{self.response_attrs['ResponseID']}"}
            )
            xmlstr = xmlstr.replace(sign_placeholder, value)
            params.update(
                {
                    'node_name' : 'urn:oasis:names:tc:SAML:2.0:protocol:Response',
                    'node_id' : f'{self.response_attrs["ResponseID"]}',
                    'statement': xmlstr
                }
            )
            xmlstr = self.crypto_backend.sign_statement(**params)

        return xmlstr


    def load_test(self, test_name=None, attributes={}, response_attrs={}):
        return SpidSpResponse(test_name,
                              authnreq_attrs = self.authnreq_attrs,
                              attributes = attributes,
                              response_attrs = response_attrs or self.response_attrs,
                              template_path = self.template_path)

    def check_response(self, res, attendeds=[]):
        if res.status_code in attendeds:
            return True, f'[http status_code: {res.status_code}]'
        else:
            return False, f'[ http status_code: {res.status_code}]'

    def send_response(self, xmlstr):
        data = {
            "RelayState": self.authn_request_data.get('RelayState', '/'),
            "SAMLResponse": base64.b64encode(xmlstr.encode())
        }
        url = self.authnreq_attrs['AssertionConsumerServiceURL']
        ua = self.authn_request_data['requests_session']
        res = ua.post(url, data=data, allow_redirects=True)
        msg = f'Response http status code [{res.status_code}]: {res.content.decode()}'
        self.logger.debug(msg)
        return res


    def test_all(self):
        for i in self.test_names:
            self.do_authnrequest()
            response_obj = self.load_test(test_name=i)
            msg = f'Response [{i}] "{response_obj.conf["description"]}"'
            xmlstr = response_obj.render()
            try:
                result = self.sign(xmlstr,
                                   key_file = response_obj.private_key)
            except XmlsecError as e:
                logger.error(
                    f'{msg}: Exception during xmlsec signature ({e})'
                )
                logger.debug('{xmlstr}')
                break

            # pretty_xml = prettify_xml(result)
            # logger.debug(pretty_xml.decode())
            logger.debug(result)

            res = self.send_response(result)
            status, status_msg = self.check_response(
                                res,
                                attendeds=response_obj.conf['status_codes']
                                )
            log_func_ = logger.info
            if status:
                pass
            elif status == False:
                log_func_ = logger.error
            elif status == None:
                log_func_ = logger.critical
            log_func_(f'{msg}: {status_msg}')
