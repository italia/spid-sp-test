import datetime
import logging
import os
import requests
import xmlschema
import sys
import subprocess

from lxml import etree
from tempfile import NamedTemporaryFile

sys.path.append(os.path.join(os.path.dirname(__file__), os.pardir))
from spid_sp_test import BASE_DIR, AbstractSpidCheck
from spid_sp_test import constants
from spid_sp_test.utils import del_ns


logger = logging.getLogger(__name__)


class SpidSpMetadataCheck(AbstractSpidCheck):
    xsds_files = [
        'saml-schema-metadata-2.0.xsd',
        'saml-schema-metadata-sp-spid-av29.xsd',
        # 'saml-schema-metadata-sp-spid-av29_old.xsd',
        'saml-schema-metadata-sp-spid.xsd',
    ]

    def __init__(self, 
                 metadata_url, 
                 xsds_files:list = None,
                 xsds_files_path:str = None,
                 verify_ssl:bool = False):
        
        super(SpidSpMetadataCheck, self).__init__(verify_ssl=verify_ssl)
        self.category = 'metadata_strict'
        
        self.logger = logger
        self.metadata_url = metadata_url
        self.metadata = self.__class__.get(metadata_url)
        self.xsds_files = xsds_files or self.xsds_files
        self.xsds_files_path = xsds_files_path or f'{BASE_DIR}/xsd'
        
        self.doc = etree.fromstring(self.metadata)
        # clean up namespace (otherwise xpath doesn't work ...)
        del_ns(self.doc)
        
        
    @staticmethod
    def get(metadata_url:str):
        if metadata_url[0:7] == 'file://':
            return open(metadata_url[7:], 'rb').read()
        else:
            return requests.get(metadata_url).content
    
    
    def xsd_check(self):
        _msg = f'Found metadata: {self.metadata}'
        self.handle_result('debug', _msg)
        os.chdir(self.xsds_files_path)
        metadata = self.metadata.decode()
        for testf in self.xsds_files:
            schema_file = open(testf, 'rb')
            msg = f'Test {self.metadata_url} with {schema_file.name}'
            try:
                schema = xmlschema.XMLSchema(schema_file)
                if not schema.is_valid(metadata):
                    schema.validate(metadata)
                    self.handle_result('error', ' '.join((msg)))
                    raise Exception('Validation Error')
                logger.info(' '.join((msg, '-> OK')))
            except Exception as e:
                logger.error(f'{msg}: {e}')
                self.handle_error(msg,
                                  description = 'xsd test failed',
                                  traceback = f'{e}')
                
        return self.is_ok(f'{self.__class__.__name__}.xsd_check')


    def test_EntityDescriptor(self):
        entity_desc = self.doc.xpath('//EntityDescriptor')
        if not self.doc.attrib.get('entityID'):
            _msg = (f'Missing entityID in {self.doc.attrib}: '
                    'The entityID attribute must be present - TR pag. 19')
            self.handle_result('error', _msg)
        elif len(entity_desc) > 1:
            _msg = 'Only one EntityDescriptor element must be present - TR pag. 19'
            self.handle_result('error', _msg)
        elif not entity_desc[0].get('entityID'):
            _msg = 'The entityID attribute must have a value - TR pag. 19'
            self.handle_result('error', _msg)
        
        self._assertIsValidHttpsUrl(
            self.doc.attrib.get('entityID'),
            'The entityID attribute must be a valid HTTPS url'
        )
        return self.is_ok(f'{self.__class__.__name__}.test_EntityDescriptor')


    def test_SPSSODescriptor(self):
        spsso = self.doc.xpath('//EntityDescriptor/SPSSODescriptor')
        self._assertTrue((len(spsso) == 1),
                         'Only one SPSSODescriptor element must be present')
        
        for attr in ['protocolSupportEnumeration', 'AuthnRequestsSigned']:
            self._assertTrue((attr in spsso[0].attrib),
                             'The %s attribute must be present - TR pag. 20' % attr)

            a = spsso[0].get(attr)
            self._assertIsNotNone(
                a,
                'The %s attribute must have a value - TR pag. 20' % attr
            )

            if attr == 'AuthnRequestsSigned':
                self._assertEqual(
                    a.lower(),
                    'true',
                    'The %s attribute must be true - TR pag. 20' % attr
                )

        return self.is_ok(f'{self.__class__.__name__}.test_SPSSODescriptor')


    def test_xmldsig(self):
        '''Verify the SP metadata signature'''
        tmp_file = NamedTemporaryFile()
        tmp_file.write(self.metadata)
        tmp_file.seek(0)

        xmlsec_cmd = ['xmlsec1',
                      '--verify',
                      '--insecure',
                      '--id-attr:ID',
                      'urn:oasis:names:tc:SAML:2.0:metadata:'
                      'EntityDescriptor',
                      tmp_file.name]
        cmd = ' '.join(xmlsec_cmd)
        is_valid = True
        msg = 'the metadata signature must be valid - TR pag. 19'

        try:
            subprocess.run(cmd, shell=True, check=True, 
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as err:
            is_valid = False
            lines = [msg]
            if err.stderr:
                stderr = (
                    'stderr: ' +
                    '\nstderr: '.join(
                        list(
                            filter(
                                None,
                                err.stderr.decode('utf-8').split('\n')
                            )
                        )
                    )
                )
                lines.append(stderr)
            if err.stdout:
                stdout = (
                    'stdout: ' +
                    '\nstdout: '.join(
                        list(
                            filter(
                                None,
                                err.stdout.decode('utf-8').split('\n')
                            )
                        )
                    )
                )
                lines.append(stdout)
            _msg = '\n'.join(lines)        
            self.handle_result('error', _msg)
            return

        xmlsec_cmd_string = ' '.join(xmlsec_cmd)
        _msg = f'{self.__class__.__name__}.test_xmldsig: OK'
        self.handle_result('info', 
                           _msg, description=f"`{xmlsec_cmd_string}`")
        return is_valid


    def test_Signature(self):
        '''Test the compliance of Signature element'''
        sign = self.doc.xpath('//EntityDescriptor/Signature')
        self._assertTrue((len(sign) == 1),
                         'The Signature element must be present - TR pag. 19')

        method = sign[0].xpath('./SignedInfo/SignatureMethod')
        self._assertTrue((len(method) == 1),
                         'The SignatureMethod element must be present - TR pag. 19')

        self._assertTrue(('Algorithm' in method[0].attrib),
                         'The Algorithm attribute must be present '
                         'in SignatureMethod element - TR pag. 19')

        alg = method[0].get('Algorithm')
        self._assertIn(alg, constants.ALLOWED_XMLDSIG_ALGS,
                       (('The signature algorithm must be one of [%s] - TR pag. 19') %
                        (', '.join(constants.ALLOWED_XMLDSIG_ALGS))))

        method = sign[0].xpath('./SignedInfo/Reference/DigestMethod')
        self._assertTrue((len(method) == 1),
                         'The DigestMethod element must be present - TR pag. 19')

        self._assertTrue(('Algorithm' in method[0].attrib),
                         'The Algorithm attribute must be present '
                         'in DigestMethod element - TR pag. 19')

        alg = method[0].get('Algorithm')
        self._assertIn(alg, constants.ALLOWED_DGST_ALGS,
                       (('The digest algorithm must be one of [%s] - TR pag. 19') %
                        (', '.join(constants.ALLOWED_DGST_ALGS))))
        
        return self.is_ok(f'{self.__class__.__name__}.test_Signature')


    def test_KeyDescriptor(self):
        '''Test the compliance of KeyDescriptor element(s)'''
        kds = self.doc.xpath('//EntityDescriptor/SPSSODescriptor'
                             '/KeyDescriptor[@use="signing"]')
        self._assertGreaterEqual(len(kds), 1,
                                 'At least one signing KeyDescriptor '
                                 'must be present - TR pag. 19')

        for kd in kds:
            certs = kd.xpath('./KeyInfo/X509Data/X509Certificate')
            self._assertGreaterEqual(len(certs), 1,
                                     'At least one signing x509 '
                                     'must be present - TR pag. 19')

        kds = self.doc.xpath('//EntityDescriptor/SPSSODescriptor'
                             '/KeyDescriptor[@use="encryption"]')

        for kd in kds:
            certs = kd.xpath('./KeyInfo/X509Data/X509Certificate')
            self._assertGreaterEqual(len(certs), 1,
                                     'At least one encryption x509 '
                                     'must be present - TR pag. 19')

        return self.is_ok(f'{self.__class__.__name__}.test_KeyDescriptor')



    def test_SingleLogoutService(self):
        '''Test the compliance of SingleLogoutService element(s)'''
        slos = self.doc.xpath('//EntityDescriptor/SPSSODescriptor'
                              '/SingleLogoutService')
        self._assertGreaterEqual(
            len(slos),
            1,
            'One or more SingleLogoutService elements must be present - AV n. 3'
        )

        for slo in slos:
            for attr in ['Binding', 'Location']:
                self._assertTrue((attr in slo.attrib),
                                 'The %s attribute '
                                 'in SingleLogoutService element '
                                 'must be present - AV n. 3' % attr)

                a = slo.get(attr)
                self._assertIsNotNone(
                    a,
                    'The %s attribute '
                    'in SingleLogoutService element '
                    'must have a value' % attr
                )

                if attr == 'Binding':
                    self._assertIn(
                        a,
                        constants.ALLOWED_SINGLELOGOUT_BINDINGS,
                        (('The %s attribute in SingleLogoutService element must be one of [%s] - AV n. 3') %  # noqa
                         (attr, ', '.join(constants.ALLOWED_BINDINGS)))  # noqa
                    )
                if attr == 'Location':
                    self._assertIsValidHttpsUrl(
                        a,
                        'The %s attribute '
                        'in SingleLogoutService element '
                        'must be a valid URL - AV n. 1 and n. 3' % attr
                    )
        return self.is_ok(f'{self.__class__.__name__}.test_SingleLogoutService')


    def test_AssertionConsumerService(self):
        '''Test the compliance of AssertionConsumerService element(s)'''
        acss = self.doc.xpath('//EntityDescriptor/SPSSODescriptor'
                              '/AssertionConsumerService')
        self._assertGreaterEqual(len(acss), 1,
                                 'At least one AssertionConsumerService '
                                 'must be present - TR pag. 20')

        for acs in acss:
            for attr in ['index', 'Binding', 'Location']:
                self._assertTrue((attr in acs.attrib),
                                 'The %s attribute must be present - TR pag. 20' % attr)
                a = acs.get(attr)
                if attr == 'index':
                    self._assertGreaterEqual(
                        int(a),
                        0,
                        'The %s attribute must be >= 0 - TR pag. 20' % attr
                    )
                elif attr == 'Binding':
                    self._assertIn(a, constants.ALLOWED_BINDINGS,
                                   (('The %s attribute must be one of [%s] - TR pag. 20') %
                                    (attr,
                                     ', '.join(constants.ALLOWED_BINDINGS))))
                elif attr == 'Location':
                    self._assertIsValidHttpsUrl(a,
                                                'The %s attribute must be a '
                                                'valid HTTPS url - TR pag. 20 and AV n. 1' % attr)
                else:
                    pass

        acss = self.doc.xpath('//EntityDescriptor/SPSSODescriptor'
                              '/AssertionConsumerService'
                              '[@isDefault="true"]')
        self._assertTrue((len(acss) == 1),
                         'Only one default AssertionConsumerService '
                         'must be present - TR pag. 20')

        acss = self.doc.xpath('//EntityDescriptor/SPSSODescriptor'
                              '/AssertionConsumerService'
                              '[@index="0"]'
                              '[@isDefault="true"]')
        self._assertTrue((len(acss) == 1),
                         'Must be present the default AssertionConsumerService '
                         'with index = 0 - TR pag. 20')
        return self.is_ok(f'{self.__class__.__name__}.test_AssertionConsumerService')


    def test_AttributeConsumingService(self):
        '''Test the compliance of AttributeConsumingService element(s)'''
        acss = self.doc.xpath('//EntityDescriptor/SPSSODescriptor'
                              '/AttributeConsumingService')
        self._assertGreaterEqual(
            len(acss),
            1,
            'One or more AttributeConsumingService elements must be present - TR pag. 20'
        )

        for acs in acss:
            self._assertTrue(('index' in acs.attrib),
                             'The index attribute '
                             'in AttributeConsumigService element '
                             'must be present')

            idx = int(acs.get('index'))
            self._assertGreaterEqual(
                idx,
                0,
                'The index attribute in AttributeConsumigService '
                'element must be >= 0 - TR pag. 20'
            )

            sn = acs.xpath('./ServiceName')
            self._assertTrue((len(sn) > 0),
                             'The ServiceName element must be present')
            for sns in sn:        
                self._assertIsNotNone(sns.text,
                                    'The ServiceName element must have a value')

            ras = acs.xpath('./RequestedAttribute')
            self._assertGreaterEqual(
                len(ras),
                1,
                'One or more RequestedAttribute elements must be present - TR pag. 20'
            )

            for ra in ras:
                self._assertTrue(('Name' in ra.attrib),
                                 'The Name attribute in '
                                 'RequestedAttribute element '
                                 'must be present - TR pag. 20 and AV n. 6')

                self._assertIn(ra.get('Name'), constants.SPID_ATTRIBUTES,
                               (('The Name attribute '
                                 'in RequestedAttribute element '
                                 'must be one of [%s] - TR pag. 20 and AV n.6') %
                                (', '.join(constants.SPID_ATTRIBUTES))))

            al = acs.xpath('RequestedAttribute/@Name')
            self._assertEqual(
                len(al),
                len(set(al)),
                'AttributeConsumigService must not contain duplicated RequestedAttribute - TR pag. 20'
            )
        return self.is_ok(f'{self.__class__.__name__}.test_AttributeConsumingService')


    def test_Organization(self):
        '''Test the compliance of Organization element'''
        orgs = self.doc.xpath('//EntityDescriptor/Organization')
        self._assertTrue((len(orgs) <= 1),
                         'Only one Organization element can be present - TR pag. 20')

        if len(orgs) == 1:
            org = orgs[0]
            for ename in ['OrganizationName', 'OrganizationDisplayName',
                          'OrganizationURL']:
                elements = org.xpath('./%s' % ename)
                self._assertGreater(
                    len(elements),
                    0,
                    'One or more %s elements must be present - TR pag. 20' % ename
                )

                for element in elements:
                    self._assertTrue(
                        ('{http://www.w3.org/XML/1998/namespace}lang' in element.attrib),  # noqa
                        'The lang attribute in %s element must be present - TR pag. 20' % ename  # noqa
                    )

                    self._assertIsNotNone(
                        element.text,
                        'The %s element must have a value  - TR pag. 20' % ename
                    )

                    if ename == 'OrganizationURL':
                        OrganizationURLvalue = element.text.strip()
                        if not (OrganizationURLvalue.startswith('http://') or OrganizationURLvalue.startswith('https://')):
                            OrganizationURLvalue = 'https://'+OrganizationURLvalue
                        self._assertIsValidHttpUrl(
                            OrganizationURLvalue,
                            'The %s -element must be a valid URL - TR pag. 20' % ename
                        )
        return self.is_ok(f'{self.__class__.__name__}.test_Organization')


    def test_all(self):
        self.xsd_check()
        
        # loop for all the attrs that starts with test_ ... todo?
        self.test_EntityDescriptor()
        self.test_SPSSODescriptor()
        self.test_xmldsig()
        self.test_Signature()
        self.test_KeyDescriptor()
        self.test_SingleLogoutService()
        self.test_AssertionConsumerService()
        self.test_AttributeConsumingService()
        self.test_Organization()
        
