from jinja2 import Environment, PackageLoader, select_autoescape
from lxml import etree

from saml2.sigver import CryptoBackendXMLSecurity
from spid_sp_test import BASE_DIR, AbstractSpidCheck
from spid_sp_test.authn_request import get_authn_request
from spid_sp_test.idp import idp
from spid_sp_test.utils import del_ns


class SpidSpResponseCheck(AbstractSpidCheck):    
    template_base_dir = f'{BASE_DIR}/responses/test/'


    def __init__(self, *args, **kwargs):
        super(SpidSpResponseCheck, self).__init__(*args, **kwargs)
        self.category = 'response'
        self.metadata_etree = kwargs.get('metadata_etree')
        self.authn_request_url = kwargs.get('authn_request_url')
        self.authn_request_data = get_authn_request(self.authn_request_url)
        self.authnreq_etree = etree.fromstring(self.authn_request_data['SAMLRequest_xml'])
        del_ns(self.authnreq_etree)
        
        self.relay_state = kwargs.get('relay_state')
        
        self.loader = Environment(
                    loader = PackageLoader('responses', 'templates'),
                    autoescape = select_autoescape(['html', 'xml'])
        )
        
        self.crypto_backend = CryptoBackendXMLSecurity()
        self.private_key_fpath = idp.SAML2_IDP_CONFIG['key_file']
        
        # with open(self.private_key_fpath) as key_str:
            # self.wrapped_private_key, self.unwrapped_private_key = get_key_pem_wrapped_unwrapped(key_str.read())

    def render(self, template:str='base.xml', data:dict={}):
        template = self.loader.get_template(template)
        result = template.render(**data)
        self.logger.debug(f"Rendering response template {template}: {result}")
        return result


    def sign(self, xmlstr, key_file=None):
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
        
        params = dict(
                        statement = xmlstr, 
                        key_file = key, 
                        node_id = 'ID'
        )
        
        params['node_name'] = 'urn:oasis:names:tc:SAML:2.0:assertion:Assertion'
        assertion_signed = self.crypto_backend.sign_statement(**params)
        
        params['node_name'] = 'urn:oasis:names:tc:SAML:2.0:protocol:Response'
        response_signed = self.crypto_backend.sign_statement(**params)
        
        return response_signed
        
        


    def test_all(self):
        xmlstr = self.render()
        result = self.sign(xmlstr)
        print(result)
