import datetime 
import os

from spid_sp_test import constants
from spid_sp_test.dump_pem import dump_metadata_pem
from spid_sp_test.utils import parse_pem

from . metadata import SpidSpMetadataCheck


class SpidSpMetadataCheckExtra(SpidSpMetadataCheck):

    def __init__(self, *args, **kwargs):
        
        super(SpidSpMetadataCheckExtra, self).__init__(*args, **kwargs)
        self.category = 'metadata_extra'

    def test_Signature_extra(self):
        '''Test the compliance of AuthnRequest element'''

        sign = self.doc.xpath('//EntityDescriptor/Signature')
        for si in sign:
            certs = si.xpath('./KeyInfo/X509Data/X509Certificate')
            
            for i in range(len(certs)):
                cert = certs[i]
                fname = dump_metadata_pem(cert, 'sp', 'signature', '/tmp')
                
                r = parse_pem(fname)
                self._assertFalse(
                    r[0].lower().startswith('sha1'),
                    ((f'The certificate #{i} must not use '
                      f'weak signature algorithm: {r[0].lower()}'))
                )
        
                exp = ['rsaEncryption', 'id-ecPublicKey']
                self._assertIn(
                    r[2],
                    exp,
                    ((f'The key type of certificate #{i} must be one of [%s] - TR pag. 19') %
                     (', '.join(exp)))
                )
        
                if r[2] == 'rsaEncryption':
                    exp = constants.MINIMUM_CERTIFICATE_LENGHT
                elif r[2] == 'id-ecPublicKey':
                    exp = 256
                else:
                    pass
                
                self._assertTrue(
                    (int(r[1]) >= exp),
                    ((f'The key length of certificate #{i} must be >= %d. Instead it is '+ r[1]) %
                     (exp))
                )
        
                self._assertTrue(
                    (datetime.datetime.strptime(r[3], "%b %d %H:%M:%S %Y") >= datetime.datetime.now()),
                    ((f'The certificate #{i} is expired. It was valid till '+r[3]))
                )
                os.remove(fname)
        return self.is_ok(f'{self.__class__.__name__}.test_Signature_extra')


    def test_SPSSODescriptor_extra(self):
        spsso = self.doc.xpath('//EntityDescriptor/SPSSODescriptor')
        for attr in ['protocolSupportEnumeration', 'WantAssertionsSigned']:
            self._assertTrue(
                (attr in spsso[0].attrib),
                'The %s attribute must be present' % attr
            )

            if attr == 'protocolSupportEnumeration':
                a = spsso[0].get(attr)
                self._assertIsNotNone(
                    a,
                    'The %s attribute must have a value' % attr
                )

                self._assertEqual(
                    a,
                    'urn:oasis:names:tc:SAML:2.0:protocol',
                    'The %s attribute must be '
                    'urn:oasis:names:tc:SAML:2.0:protocol' % attr
                )

            if attr == 'WantAssertionsSigned':
                a = spsso[0].get(attr)
                self._assertIsNotNone(
                    a,
                    'The %s attribute must have a value' % attr
                )
                
                if a:
                    self._assertEqual(
                        a.lower(),
                        'true',
                        'The %s attribute must be true' % attr
                    )
        return self.is_ok(f'{self.__class__.__name__}.test_SPSSODescriptor_extra')


    def test_AttributeConsumingService_extra(self):
        acss = self.doc.xpath('//EntityDescriptor/SPSSODescriptor'
                              '/AssertionConsumerService')
        for acs in acss:
            ras = acs.xpath('./RequestedAttribute')
            for ra in ras:
                a = ra.get('NameFormat')
                if a is not None:
                    self._assertIn(
                        a,
                        common.constants.ALLOWED_FORMATS,
                        (('The NameFormat attribute '
                          'in RequestedAttribute element '
                          'must be one of [%s]') %
                         (', '.join(common.constants.ALLOWED_FORMATS)))
                    )
        return self.is_ok(f'{self.__class__.__name__}.test_AttributeConsumingService_extra')

    
    def test_Organization_extra(self):
        orgs = self.doc.xpath('//EntityDescriptor/Organization')
        self._assertTrue((len(orgs) == 1), 'An Organization must be present')
        
        if orgs:
            org = orgs[0]
            for elem in ['Name', 'URL', 'DisplayName']:
                e = org.xpath(
                    './Organization%s[@xml:lang="it"]' % elem,
                    namespaces={
                        'xml': 'http://www.w3.org/XML/1998/namespace',
                    }
                )
                self._assertTrue(
                    (len(e) == 1),
                    'An IT localised Organization%s must be present' % elem
                )
            return self.is_ok(f'{self.__class__.__name__}.test_Organization')


    def test_all(self):

        self.test_Signature_extra()
        self.test_AttributeConsumingService_extra()
        self.test_SPSSODescriptor_extra()
        self.test_Organization_extra()
