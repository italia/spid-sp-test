import base64
import copy
import datetime
import logging
import os
import requests
import xmlschema
import sys
import subprocess
import urllib

from lxml import etree

from saml2 import BINDING_HTTP_POST
from saml2.server import Server
# from saml2.s_utils import OtherError
from saml2.sigver import CryptoBackendXMLSecurity
# from saml2.sigver import CryptoBackendXmlSec1
sys.path.append(os.path.join(os.path.dirname(__file__), os.pardir))
from spid_sp_test import BASE_DIR, AbstractSpidCheck
from spid_sp_test import constants
from spid_sp_test.idp.idp import SAML2_IDP_CONFIG
from spid_sp_test.utils import (decode_samlreq,
                                del_ns, 
                                parse_pem, 
                                samlreq_from_htmlform,
                                relaystate_from_htmlform,
                                decode_authn_req_http_redirect)


from . exceptions import SAMLRequestNotFound


logger = logging.getLogger(__name__)


def get_authn_request(authn_request_url, verify_ssl):
    status = None
    data = {}
    binding = 'post' or 'redirect'
    if authn_request_url[0:7] == 'file://':
        authn_request = open(authn_request_url[7:], 'rb').read()
        if authn_request[0] == b'<' and authn_request[-1] == b'>':
            binding = 'post'
        else:
            binding = 'redirect'

    else:
        request = requests.get(
                                authn_request_url, 
                                verify=verify_ssl,
                                allow_redirects=False
        )
    
    if binding == 'redirect':
        # HTTP-REDIRECT
        redirect = request.headers['Location']
        q_args = urllib.parse.splitquery(redirect)[1]
        authn_request = dict(urllib.parse.parse_qsl(q_args))
        
        data['SAMLRequest'] = authn_request['SAMLRequest']
        data['SAMLRequest_xml'] = decode_authn_req_http_redirect(authn_request['SAMLRequest'])
        data['RelayState'] = authn_request['RelayState']
        data['SigAlg'] = authn_request['SigAlg']
        data['Signature'] = authn_request['Signature']
        
    elif binding == 'post':
        # HTTP POST
        authn_request = request.content.decode()
        data['SAMLRequest'] = samlreq_from_htmlform(authn_request)
        data['SAMLRequest_xml'] = decode_samlreq(authn_request)
        data['RelayState'] = relaystate_from_htmlform(authn_request)
    else:
        raise SAMLRequestNotFound()

    return data


class SpidSpAuthnReqCheck(AbstractSpidCheck):
    xsds_files = [
        'saml-schema-protocol-2.0.xsd',
    ]
    
    def __init__(self, 
                 metadata,
                 authn_request_url:str = None, 
                 authn_request:dict = {},
                 xsds_files:list = None,
                 xsds_files_path:str = None,
                 verify_ssl:bool = False):
        
        super(SpidSpAuthnReqCheck, self).__init__(verify_ssl=verify_ssl)
        self.category = 'authnrequest_strict'
        
        self.logger = logger
        self.metadata = metadata
        
        self.authn_request = get_authn_request(authn_request_url,
                                               verify_ssl=verify_ssl)
        
        try:
            self.authn_request_decoded = self.authn_request['SAMLRequest_xml'] 
            self.authn_request_encoded = self.authn_request['SAMLRequest'] 
        except KeyError as e:
            raise SAMLRequestNotFound(self.authn_request)
        
        self.relay_state = self.authn_request.get('RelayState')

        self.xsds_files = xsds_files or self.xsds_files
        self.xsds_files_path = xsds_files_path or f'{BASE_DIR}/xsd'
        
        self.md = etree.fromstring(self.metadata)
        del_ns(self.md)
        
        self.doc = etree.fromstring(self.authn_request_decoded)
        # clean up namespace (otherwise xpath doesn't work ...)
        del_ns(self.doc)
        
        # binding detection
        self.IS_HTTP_REDIRECT = self.authn_request.get('Signature')
        # HTTP-REDIRECT params
        self.params = {'RelayState': self.relay_state}


    def idp(self):
        idp_config = copy.deepcopy(SAML2_IDP_CONFIG)        
        idp_server = Server(idp_config)
        if self.metadata:
            idp_server.metadata.imp(
                [
                    {"class": "saml2.mdstore.InMemoryMetaData", 
                     "metadata": [(self.metadata,)]
                    }
                ]
            )
        return idp_server


    def test_xsd_and_xmldsig(self):
        '''Test if the XSD validates and if the signature is valid'''

        msg = ('The AuthnRequest must validate against XSD ' +
               'and must have a valid signature')

        os.chdir(self.xsds_files_path)
        authn_request = self.authn_request_decoded.decode()
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
            self.handle_result('error', 
                               '-> '.join((msg, f'{e}')))
      
        cert = self.md.xpath('//SPSSODescriptor/KeyDescriptor[@use="signing"]'
                             '/KeyInfo/X509Data/X509Certificate/text()')[0]
        
        # pyXMLSecurity allows to pass a certificate without store it on a file
        # backend = CryptoBackendXmlSec1(xmlsec_binary='/usr/bin/xmlsec1')
        backend = CryptoBackendXMLSecurity()
        is_valid = backend.validate_signature(self.authn_request_decoded,
                                              cert_file=cert,
                                              cert_type='pem', 
                                              node_name=constants.NODE_NAME,
                                              node_id=None)
        self._assertTrue(is_valid, 'AuthnRequest Signature validation failed')
        return self.is_ok(f'{self.__class__.__name__}.test_xsd_and_xmldsig')


    def test_AuthnRequest(self):
        '''Test the compliance of AuthnRequest element'''
        req = self.doc.xpath('/AuthnRequest')
        self._assertTrue(
            (len(req) == 1),
            'One AuthnRequest element must be present'
        )

        req = req[0]

        for attr in ['ID', 'Version', 'IssueInstant', 'Destination']:
            self._assertTrue(
                (attr in req.attrib),
                'The %s attribute must be present - TR pag. 8 ' % attr
            )

            value = req.get(attr)
            if (attr == 'ID'):
                self._assertIsNotNone(
                    value,
                    'The %s attribute must have a value - TR pag. 8 ' % attr
                )

            if (attr == 'Version'):
                exp = '2.0'
                self._assertEqual(
                    value,
                    exp,
                    'The %s attribute must be %s - TR pag. 8 ' % (attr, exp)
                )

            if (attr == 'IssueInstant'):
                self._assertIsNotNone(
                    value,
                    'The %s attribute must have a value - TR pag. 8 ' % attr
                )
                self._assertTrue(
                    bool(constants.UTC_STRING.search(value)),
                    'The %s attribute must be a valid UTC string - TR pag. 8 ' % attr
                )

            if (attr == 'Destination'):
                self._assertIsNotNone(
                    value,
                    'The %s attribute must have a value - TR pag. 8 ' % attr
                )
                self._assertIsValidHttpsUrl(
                    value,
                    'The %s attribute must be a valid HTTPS url - TR pag. 8 ' % attr
                )

        self._assertTrue(
            ('IsPassive' not in req.attrib),
            'The IsPassive attribute must not be present - TR pag. 9 '
        )

        level = req.xpath('//RequestedAuthnContext'
                          '/AuthnContextClassRef')[0].text
        if bool(constants.SPID_LEVEL_23.search(level)):
            self._assertTrue(
                ('ForceAuthn' in req.attrib),
                'The ForceAuthn attribute must be present if SPID level > 1 - TR pag. 8 '
            )
            value = req.get('ForceAuthn')
            self._assertTrue(
                (value.lower() in constants.BOOLEAN_TRUE),
                'The ForceAuthn attribute must be true or 1 - TR pag. 8 '
            )

        attr = 'AssertionConsumerServiceIndex'
        if attr in req.attrib:
            value = req.get(attr)
            availableassertionindexes = []

            acss = self.md.xpath('//EntityDescriptor/SPSSODescriptor'
                                 '/AssertionConsumerService')
            for acs in acss:
                index = acs.get('index')
                availableassertionindexes.append(index)

            self._assertIsNotNone(
                value,
                'The %s attribute must have a value- TR pag. 8 ' % attr
            )
            self._assertGreaterEqual(
                int(value),
                0,
                'The %s attribute must be >= 0 - TR pag. 8 and pag. 20' % attr
            )
            self._assertTrue(value in availableassertionindexes,
                'The %s attribute must be equal to an AssertionConsumerService index - TR pag. 8 ' % attr
            )
        else:
            availableassertionlocations = []

            acss = self.md.xpath('//EntityDescriptor/SPSSODescriptor'
                                 '/AssertionConsumerService')
            for acs in acss:
                location = acs.get('Location')
                availableassertionlocations.append(location)

            for attr in ['AssertionConsumerServiceURL', 'ProtocolBinding']:
                self._assertTrue(
                    (attr in req.attrib),
                    'The %s attribute must be present - TR pag. 8 ' % attr
                )

                value = req.get(attr)

                self._assertIsNotNone(
                    value,
                    'The %s attribute must have a value - TR pag. 8 ' % attr
                )

                if attr == 'AssertionConsumerServiceURL':
                    self._assertIsValidHttpsUrl(
                        value,
                        'The %s attribute must be a valid HTTPS url - TR pag. 8 and pag. 16' % attr
                    )

                    self._assertTrue(value in availableassertionlocations,
                        'The %s attribute must be equal to an AssertionConsumerService Location - TR pag. 8 ' % attr
                    )

                if attr == 'ProtocolBinding':
                    exp = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
                    self._assertEqual(
                        value,
                        exp,
                        'The %s attribute must be %s - TR pag. 8 ' % (attr, exp)
                    )

        attr = 'AttributeConsumingServiceIndex'
        if attr in req.attrib:
            availableattributeindexes = []

            acss = self.md.xpath('//EntityDescriptor/SPSSODescriptor'
                                 '/AttributeConsumingService')
            for acs in acss:
                index = acs.get('index')
                availableattributeindexes.append(index)

            value = req.get(attr)
            self._assertIsNotNone(
                value,
                'The %s attribute must have a value - TR pag. 8' % attr
            )
            self._assertGreaterEqual(
                int(value),
                0,
                'The %s attribute must be >= 0 - TR pag. 8 and pag. 20' % attr
            )
            self._assertTrue(value in availableattributeindexes,
                'The %s attribute must be equal to an AttributeConsumingService index - TR pag. 8 ' % attr
            )
        return self.is_ok(f'{self.__class__.__name__}.test_AuthnRequest')


    def test_Subject(self):
        '''Test the compliance of Subject element'''

        subj = self.doc.xpath('//AuthnRequest/Subject')
        if len(subj) > 1:
            self._assertEqual(
                len(subj),
                1,
                'Only one Subject element can be present - TR pag. 9'
            )

        if len(subj) == 1:
            subj = subj[0]
            name_id = subj.xpath('./NameID')
            self._assertEqual(
                len(name_id),
                1,
                'One NameID element in Subject element must be present - TR pag. 9'
            )
            name_id = name_id[0]
            for attr in ['Format', 'NameQualifier']:
                self._assertTrue(
                    (attr in name_id.attrib),
                    'The %s attribute must be present - TR pag. 9' % attr
                )

                value = name_id.get(attr)

                self._assertIsNotNone(
                    value,
                    'The %s attribute must have a value - TR pag. 9' % attr
                )

                if attr == 'Format':
                    exp = ('urn:oasis:names:tc:SAML:1.1:nameid-format'
                           ':unspecified')
                    self._assertEqual(
                        value,
                        exp,
                        'The % attribute must be %s - TR pag. 9' % (attr, exp)
                    )
        return self.is_ok(f'{self.__class__.__name__}.test_Subject')


    def test_Issuer(self):
        '''Test the compliance of Issuer element'''

        e = self.doc.xpath('//AuthnRequest/Issuer')
        self._assertTrue(
            (len(e) == 1),
            'One Issuer element must be present - TR pag. 9'
        )

        e = e[0]

        self._assertIsNotNone(
            e.text,
            'The Issuer element must have a value - TR pag. 9'
        )

        entitydescriptor = self.md.xpath('//EntityDescriptor')
        entityid = entitydescriptor[0].get('entityID')
        self._assertEqual(e.text, entityid, 'The Issuer\'s value must be equal to entityID - TR pag. 9')

        for attr in ['Format', 'NameQualifier']:
            self._assertTrue(
                (attr in e.attrib),
                'The %s attribute must be present - TR pag. 9' % attr
            )

            value = e.get(attr)

            self._assertIsNotNone(
                value,
                'The %s attribute must have a value - TR pag. 9' % attr
            )

            if attr == 'Format':
                exp = 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity'
                self._assertEqual(
                    value,
                    exp,
                    'The %s attribute must be %s - TR pag. 9' % (attr, exp)
                )
        return self.is_ok(f'{self.__class__.__name__}.test_Issuer')


    def test_NameIDPolicy(self):
        '''Test the compliance of NameIDPolicy element'''

        e = self.doc.xpath('//AuthnRequest/NameIDPolicy')
        self._assertTrue(
            (len(e) == 1),
            'One NameIDPolicy element must be present - TR pag. 9'
        )

        e = e[0]

        self._assertTrue(
            ('AllowCreate' not in e.attrib),
            'The AllowCreate attribute must not be present - AV n.5 '
        )

        attr = 'Format'
        self._assertTrue(
            (attr in e.attrib),
            'The %s attribute must be present - TR pag. 9' % attr
        )

        value = e.get(attr)

        self._assertIsNotNone(
            value,
            'The %s attribute must have a value - TR pag. 9' % attr
        )

        if attr == 'Format':
            exp = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
            self._assertEqual(
                value,
                exp,
                'The %s attribute must be %s - TR pag. 9' % (attr, exp)
            )
        return self.is_ok(f'{self.__class__.__name__}.test_NameIDPolicy')


    def test_Conditions(self):
        '''Test the compliance of Conditions element'''
        e = self.doc.xpath('//AuthnRequest/Conditions')

        if len(e) > 1:
            self._assertEqual(
                len(1),
                1,
                'Only one Conditions element is allowed - TR pag. 9'
            )

        if len(e) == 1:
            e = e[0]
            for attr in ['NotBefore', 'NotOnOrAfter']:
                self._assertTrue(
                    (attr in e.attrib),
                    'The %s attribute must be present - TR pag. 9' % attr
                )

                value = e.get(attr)

                self._assertIsNotNone(
                    value,
                    'The %s attribute must have a value - TR pag. 9' % attr
                )

                self._assertTrue(
                    bool(common.regex.UTC_STRING.search(value)),
                    'The %s attribute must have avalid UTC string - TR pag. 9' % attr
                )
        return self.is_ok(f'{self.__class__.__name__}.test_Conditions')


    def test_RequestedAuthnContext(self):
        '''Test the compliance of RequestedAuthnContext element'''

        e = self.doc.xpath('//AuthnRequest/RequestedAuthnContext')
        self._assertEqual(
            len(e),
            1,
            'Only one RequestedAuthnContext element must be present - TR pag. 9'
        )

        e = e[0]

        attr = 'Comparison'
        self._assertTrue(
            (attr in e.attrib),
            'The %s attribute must be present - TR pag. 10' % attr
        )

        value = e.get(attr)
        self._assertIsNotNone(
            value,
            'The %s attribute must have a value - TR pag. 10' % attr
        )

        allowed = ['exact', 'minimum', 'better', 'maximum']
        self._assertIn(
            value,
            allowed,
            (('The %s attribute must be one of [%s] - TR pag. 10') %
             (attr, ', '.join(allowed)))
        )

        acr = e.xpath('./AuthnContextClassRef')
        self._assertEqual(
            len(acr),
            1,
            'Only one AuthnContexClassRef element must be present - TR pag. 9'
        )

        acr = acr[0]

        self._assertIsNotNone(
            acr.text,
            'The AuthnContexClassRef element must have a value - TR pag. 9'
        )

        self._assertTrue(
            bool(constants.SPID_LEVEL_ALL.search(acr.text)),
            'The AuthnContextClassRef element must have a valid SPID level - TR pag. 9 and AV n.5'
        )
        return self.is_ok(f'{self.__class__.__name__}.test_RequestedAuthnContext')


    def test_Signature(self):
        '''Test the compliance of Signature element'''

        if not self.IS_HTTP_REDIRECT:
            sign = self.doc.xpath('//AuthnRequest/Signature')
            self._assertTrue((len(sign) == 1),
                             'The Signature element must be present - TR pag. 10')

            method = sign[0].xpath('./SignedInfo/SignatureMethod')
            self._assertTrue((len(method) == 1),
                             'The SignatureMethod element must be present- TR pag. 10')

            self._assertTrue(('Algorithm' in method[0].attrib),
                             'The Algorithm attribute must be present '
                             'in SignatureMethod element - TR pag. 10')

            alg = method[0].get('Algorithm')
            self._assertIn(alg, constants.ALLOWED_XMLDSIG_ALGS,
                           (('The signature algorithm must be one of [%s] - TR pag. 10') %
                            (', '.join(constants.ALLOWED_XMLDSIG_ALGS))))  # noqa

            method = sign[0].xpath('./SignedInfo/Reference/DigestMethod')
            self._assertTrue((len(method) == 1),
                             'The DigestMethod element must be present')

            self._assertTrue(('Algorithm' in method[0].attrib),
                             'The Algorithm attribute must be present '
                             'in DigestMethod element - TR pag. 10')

            alg = method[0].get('Algorithm')
            self._assertIn(alg, constants.ALLOWED_DGST_ALGS,
                           (('The digest algorithm must be one of [%s] - TR pag. 10') %
                            (', '.join(constants.ALLOWED_DGST_ALGS))))

            # save the grubbed certificate for future alanysis
            # cert = sign[0].xpath('./KeyInfo/X509Data/X509Certificate')[0]
            # dump_pem.dump_request_pem(cert, 'authn', 'signature', DATA_DIR)
        return self.is_ok(f'{self.__class__.__name__}.test_Signature')


    def test_RelayState(self):
        '''Test the compliance of RelayState parameter'''

        if ('RelayState' in self.params):
            relaystate = self.params.get('RelayState')
            self._assertTrue(
                (relaystate.find('http') == -1 ),
                'RelayState must not be immediately intelligible - TR pag. 14 or pag. 15'
            )
        else:
            self._assertTrue(False, 'RelayState is missing - TR pag. 14 or pag. 15')
        return self.is_ok(f'{self.__class__.__name__}.test_RelayState')
        
    def test_Scoping(self):
        '''Test the compliance of Scoping element'''

        e = self.doc.xpath('//AuthnRequest/Scoping')
        self._assertEqual(
            len(e),
            0,
            'The Scoping element must not be present - AV n.5'
        )
        return self.is_ok(f'{self.__class__.__name__}.test_Scoping')
        
    def test_RequesterID(self):
        '''Test the compliance of RequesterID element'''

        e = self.doc.xpath('//AuthnRequest/RequesterID')
        self._assertEqual(
            len(e),
            0,
            'The RequesterID  element must not be present - AV n.5'
        )
        return self.is_ok(f'{self.__class__.__name__}.test_RequesterID')

    def test_all(self):
        
        self.test_xsd_and_xmldsig()
        self.test_AuthnRequest()
        self.test_Subject()
        self.test_Issuer()
        self.test_NameIDPolicy()
        self.test_Conditions()
        self.test_RequestedAuthnContext()
        self.test_Signature()
        self.test_RelayState()
        self.test_Scoping()
        self.test_RequesterID()
