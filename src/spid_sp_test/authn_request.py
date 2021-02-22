import base64
import datetime
import logging
import os
import requests
import xmlschema
import sys
import subprocess

from lxml import etree

from saml2 import BINDING_HTTP_POST
sys.path.append(os.path.join(os.path.dirname(__file__), os.pardir))
from spid_sp_test import BASE_DIR, AbstractSpidCheck
from spid_sp_test import constants
from spid_sp_test.idp.idp import IDP_SERVER
from spid_sp_test.utils import del_ns, parse_pem, samlreq_from_htmlform


logger = logging.getLogger(__name__)


class SpidSpAuthnReqCheck(AbstractSpidCheck):
    xsds_files = [
        'saml-schema-protocol-2.0.xsd',
    ]
    
    def __init__(self, 
                 authn_request_url, 
                 xsds_files:list = None,
                 xsds_files_path:str = None,
                 extra:bool=False):
        
        super(SpidSpAuthnReqCheck, self).__init__(extra=extra)
        
        self.logger = logger
        self.authn_request_url = authn_request_url
        self.authn_request = self.__class__.get(authn_request_url)
        self.xsds_files = xsds_files or self.xsds_files
        self.xsds_files_path = xsds_files_path or f'{BASE_DIR}/xsd'
        
        # self.doc = etree.fromstring(self.metadata)
        # clean up namespace (otherwise xpath doesn't work ...)
        # del_ns(self.doc)
    
    @staticmethod
    def get(authn_request_url):
        page = requests.get(authn_request_url, allow_redirects=True, verify=False).content.decode()
        saml_req = samlreq_from_htmlform(page)
        return saml_req
    
    def test_xsd_and_xmldsig(self):
        '''Test if the XSD validates and if the signature is valid'''

        msg = ('The AuthnRequest must validate against XSD ' +
               'and must have a valid signature')

        os.chdir(self.xsds_files_path)
        authn_request = self.authn_request
        schema_file = open('saml-schema-protocol-2.0.xsd', 'rb')
        msg = f'Test authn_request with {schema_file.name}'
        try:
            schema = xmlschema.XMLSchema(schema_file)
            if not schema.is_valid(authn_request):
                schema.validate(authn_request)
                self.handle_result('error', 
                                   ' '.join((msg, '-> FAILED!')))
                raise Exception('Validation Error')
            logger.info(' '.join((msg, '-> OK')))
        except Exception as e:
            self.handle_result('critical', 
                               '-> '.join((msg, f'{e}')))
        
        # pysaml2 auth req object with signature check
        req_obj = IDP_SERVER.parse_authn_request(self.authn_request, 
                                                 BINDING_HTTP_POST)
        breakpoint()
        
        return self.is_ok(f'{self.__class__.__name__}.test_xsd_and_xmldsig : OK')
    
    def test_all(self):
        
        self.test_xsd_and_xmldsig()
