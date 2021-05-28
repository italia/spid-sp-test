from spid_sp_test.utils import del_ns
from spid_sp_test import constants
from spid_sp_test import BASE_DIR, AbstractSpidCheck
import logging
import os
import requests
import xmlschema
import sys
import subprocess
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lxml import etree
from tempfile import NamedTemporaryFile

sys.path.append(os.path.join(os.path.dirname(__file__), os.pardir))


logger = logging.getLogger(__name__)


class SpidSpMetadataCheck(AbstractSpidCheck):

    def __init__(self,
                 metadata_url,
                 xsds_files: list = None,
                 xsds_files_path: str = None,
                 production: bool = False):

        super(SpidSpMetadataCheck, self).__init__(verify_ssl=production)
        self.category = 'metadata_strict'

        self.logger = logger
        self.metadata_url = metadata_url
        self.production = production
        self.metadata = self.get(metadata_url)
        self.xsds_files_path = xsds_files_path or f'{BASE_DIR}/xsd'

        self.doc = etree.fromstring(self.metadata)
        # clean up namespace (otherwise xpath doesn't work ...)
        del_ns(self.doc)

    def get(self, metadata_url: str):
        if metadata_url[0:7] == 'file://':
            return open(metadata_url[7:], 'rb').read()
        else:
            request = requests.get(metadata_url,
                                   allow_redirects = True,
                                   verify=self.production)
            if request.status_code != 200:
                raise Exception(
                    f'Metadata not found: server response with code {request.status_code}'
                )
            else:
                return request.content

    def xsd_check(self,
                  xsds_files:list = ['saml-schema-metadata-2.0.xsd']):
        _msg = f'Found metadata'
        self.handle_result('debug',
                           _msg,
                           description = self.metadata.decode())
        _orig_pos = os.getcwd()
        os.chdir(self.xsds_files_path)
        metadata = self.metadata.decode()
        for testf in xsds_files:
            try:
                schema_file = open(testf, 'rb')
                msg = f'Test {self.metadata_url} with {schema_file.name}'
                schema = xmlschema.XMLSchema(schema_file)
                if not schema.is_valid(metadata):
                    schema.validate(metadata)
                    self.handle_result('error', ' '.join((msg)))
                    # raise Exception('Validation Error')
                logger.info(' '.join((msg, '-> OK')))
                break
            except Exception as e:
                os.chdir(_orig_pos)
                logger.error(f'{msg}: {e}')
                self.handle_error(msg,
                                  description='xsd test failed',
                                  traceback=f'{e}')
        os.chdir(_orig_pos)
        return self.is_ok(f'{self.__class__.__name__}.xsd_check')

    def test_EntityDescriptor(self):
        entity_desc = self.doc.xpath('//EntityDescriptor')
        desc = [etree.tostring(ent).decode() for ent in entity_desc if entity_desc]
        error_kwargs = dict(description = desc) if desc else {}
        if not self.doc.attrib.get('entityID'):
            _msg = (f'Missing entityID in {self.doc.attrib}: '
                    'The entityID attribute MUST be present - TR pag. 19')
            self.handle_result('error', _msg, **error_kwargs)
        elif len(entity_desc) > 1:
            _msg = 'Only one EntityDescriptor element MUST be present - TR pag. 19'
            self.handle_result('error', _msg, **error_kwargs)
        elif not entity_desc[0].get('entityID'):
            _msg = 'The entityID attribute MUST have a value - TR pag. 19'
            self.handle_result('error', _msg, **error_kwargs)

        if self.production:
            self._assertIsValidHttpsUrl(
                self.doc.attrib.get('entityID'),
                'The entityID attribute MUST be a valid HTTPS url'
            )

        self._assertTrue((self.doc.attrib.get('entityID') == self.metadata_url),
                         f'The EntityID MUST be equal to {self.metadata_url}',
                         description=f"{self.doc.attrib.get('entityID')}",
                         level='warning')

        return self.is_ok(f'{self.__class__.__name__}.test_EntityDescriptor')

    def test_SPSSODescriptor(self):
        spsso = self.doc.xpath('//EntityDescriptor/SPSSODescriptor')
        desc = [etree.tostring(ent).decode() for ent in spsso if spsso]
        error_kwargs = dict(description = desc) if desc else {}

        self._assertTrue((len(spsso) == 1),
                         'Only one SPSSODescriptor element MUST be present',
                         **error_kwargs)
        return self.is_ok(f'{self.__class__.__name__}.test_SPSSODescriptor')

    def test_SPSSODescriptor_SPID(self):
        spsso = self.doc.xpath('//EntityDescriptor/SPSSODescriptor')
        desc = [etree.tostring(ent).decode() for ent in spsso if spsso]
        error_kwargs = dict(description = desc) if desc else {}

        for attr in ['protocolSupportEnumeration', 'AuthnRequestsSigned']:
            self._assertTrue((attr in spsso[0].attrib),
                             f'The {attr} attribute MUST be present - TR pag. 20',
                             **error_kwargs)

            a = spsso[0].get(attr)
            self._assertIsNotNone(
                a,
                f'The {attr} attribute MUST have a value - TR pag. 20',
                **error_kwargs)

            if attr == 'AuthnRequestsSigned' and a:
                self._assertEqual(
                    a.lower(),
                    'true',
                    f'The {attr} attribute MUST be true - TR pag. 20',
                    **error_kwargs)

        return self.is_ok(
            f'{self.__class__.__name__}.test_SPSSODescriptor_SPID')


    def test_NameIDFormat_Transient(self):
        spsso = self.doc.xpath('//EntityDescriptor/SPSSODescriptor/NameIDFormat')
        desc = [etree.tostring(ent).decode() for ent in spsso if spsso]
        error_kwargs = dict(description = desc) if desc else {}

        if spsso:
            _rule = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
            self._assertTrue(
                (spsso[0].text == _rule),
                f'The NameIDFormat MUST {_rule}',
                **error_kwargs)

        return self.is_ok(
            f'{self.__class__.__name__}.test_NameIDFormat_SPID')


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
        msg = 'the metadata signature MUST be valid - TR pag. 19'

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
                                err.stderr.decode('utf-8').split(r'\n')
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
                                err.stdout.decode('utf-8').split(r'\n')
                            )
                        )
                    )
                )
                lines.append(stdout)
            _msg = '\n'.join(lines)
            self.handle_result('error', msg,
                               description='Description',
                               traceback=_msg)
            return

        xmlsec_cmd_string = ' '.join(xmlsec_cmd)
        _msg = f'{self.__class__.__name__}.test_xmldsig: OK'
        self.handle_result('info',
                           _msg, description=f"`{xmlsec_cmd_string}`")
        return is_valid

    def test_Signature(self):
        '''Test the compliance of Signature element'''
        sign = self.doc.xpath('//EntityDescriptor/Signature')
        desc = [etree.tostring(ent).decode() for ent in sign if sign]
        error_kwargs = dict(description = desc) if desc else {}
        self._assertTrue((len(sign) > 0),
                         'The Signature element MUST be present - TR pag. 19',
                         **error_kwargs)

        error_kwargs = dict(description = desc, traceback = '')
        if not sign:
            self.handle_result(
                'error',
                'The SignatureMethod element MUST be present - TR pag. 19',
                **error_kwargs)
            self.handle_result(
                'error',
                'The Algorithm attribute MUST be present in SignatureMethod element - TR pag. 19',
                **error_kwargs)
            self.handle_result(
                'error',
                "The signature algorithm MUST be valid - TR pag. 19",
                description = f"Must be one of [{', '.join(constants.ALLOWED_XMLDSIG_ALGS)}]")

            self.handle_result(
                'error',
                'The Algorithm attribute MUST be present in DigestMethod element - TR pag. 19',
                **error_kwargs)
            self.handle_result(
                'error',
                f"The digest algorithm MUST be valid - TR pag. 19",
                description = f"Must be one of [{', '.join(constants.ALLOWED_DGST_ALGS)}]")
        else:
            method = sign[0].xpath('./SignedInfo/SignatureMethod')
            desc = [etree.tostring(ent).decode() for ent in method if method]
            error_kwargs = dict(description = desc) if desc else {}
            self._assertTrue((len(method) > 0),
                             'The SignatureMethod element MUST be present - TR pag. 19',
                             **error_kwargs)

            self._assertTrue(('Algorithm' in method[0].attrib),
                             'The Algorithm attribute MUST be present '
                             'in SignatureMethod element - TR pag. 19',
                             **error_kwargs)

            alg = method[0].get('Algorithm')
            self._assertIn(alg, constants.ALLOWED_XMLDSIG_ALGS,
                           'The signature algorithm MUST be valid - TR pag. 19',
                           description = f"One of {(', '.join(constants.ALLOWED_XMLDSIG_ALGS))}"
            )

            method = sign[0].xpath('./SignedInfo/Reference/DigestMethod')
            self._assertTrue((len(method) == 1),
                             'The DigestMethod element MUST be present - TR pag. 19',
                             **error_kwargs)

            self._assertTrue(('Algorithm' in method[0].attrib),
                             'The Algorithm attribute MUST be present '
                             'in DigestMethod element - TR pag. 19',
                             **error_kwargs)

            alg = method[0].get('Algorithm')
            self._assertIn(alg, constants.ALLOWED_DGST_ALGS,
                           'The digest algorithm MUST be valid - TR pag. 19',
                           description = f"One of {(', '.join(constants.ALLOWED_DGST_ALGS))}",
            )


        return self.is_ok(f'{self.__class__.__name__}.test_Signature')

    def test_KeyDescriptor(self):
        '''Test the compliance of KeyDescriptor element(s)'''
        kds = self.doc.xpath('//EntityDescriptor/SPSSODescriptor'
                             '/KeyDescriptor[@use="signing"]')
        self._assertGreaterEqual(
            len(kds), 1,
            'At least one signing KeyDescriptor MUST be present - TR pag. 19'
        )

        desc = [etree.tostring(ent).decode() for ent in kds if kds]
        error_kwargs = dict(description = desc, traceback = '')

        for kd in kds:
            certs = kd.xpath('./KeyInfo/X509Data/X509Certificate')
            self._assertGreaterEqual(
                len(certs), 1,
                'At least one signing x509 MUST be present - TR pag. 19',
                **error_kwargs)

        kds = self.doc.xpath('//EntityDescriptor/SPSSODescriptor'
                             '/KeyDescriptor[@use="encryption"]')

        for kd in kds:
            certs = kd.xpath('./KeyInfo/X509Data/X509Certificate')
            self._assertGreaterEqual(
                len(certs), 1,
                'At least one encryption x509 MUST be present - TR pag. 19',
                **error_kwargs)

        return self.is_ok(f'{self.__class__.__name__}.test_KeyDescriptor')

    def test_SingleLogoutService(self):
        '''Test the compliance of SingleLogoutService element(s)'''
        slos = self.doc.xpath('//EntityDescriptor/SPSSODescriptor'
                              '/SingleLogoutService')
        self._assertGreaterEqual(
            len(slos),
            1,
            'One or more SingleLogoutService elements MUST be present - AV n. 3'
        )

        desc = [etree.tostring(ent).decode() for ent in slos if slos]
        error_kwargs = dict(description = desc)

        for slo in slos:
            for attr in ['Binding', 'Location']:
                self._assertTrue(
                    (attr in slo.attrib),
                    f'The {attr} attribute in SingleLogoutService element MUST be present - AV n. 3',
                    **error_kwargs)

                a = slo.get(attr)
                self._assertIsNotNone(
                    a,
                    f'The {attr} attribute in SingleLogoutService element MUST have a value',
                    **error_kwargs
                )

                if attr == 'Binding':
                    self._assertIn(
                        a,
                        constants.ALLOWED_SINGLELOGOUT_BINDINGS,
                        (('The %s attribute in SingleLogoutService element MUST be one of [%s] - AV n. 3') %  # noqa
                         (attr, ', '.join(constants.ALLOWED_BINDINGS))),
                        **error_kwargs # noqa
                    )
                if attr == 'Location' and self.production:
                    self._assertIsValidHttpsUrl(
                        a,
                        f'The {attr} attribute '
                        'in SingleLogoutService element '
                        'MUST be a valid HTTPS URL - AV n. 1 and n. 3',
                        **error_kwargs
                    )
        return self.is_ok(f'{self.__class__.__name__}.test_SingleLogoutService')

    def test_AssertionConsumerService(self):
        '''Test the compliance of AssertionConsumerService element(s)'''
        acss = self.doc.xpath('//EntityDescriptor/SPSSODescriptor'
                              '/AssertionConsumerService')

        desc = [etree.tostring(ent).decode() for ent in acss if acss]
        error_kwargs = dict(description = desc) if desc else {}

        self._assertGreaterEqual(len(acss), 1,
                                 'At least one AssertionConsumerService '
                                 'MUST be present - TR pag. 20')

        for acs in acss:
            for attr in ['index', 'Binding', 'Location']:
                self._assertTrue(
                    (attr in acs.attrib),
                    f'The {attr} attribute MUST be present - TR pag. 20'
                )
                a = acs.get(attr)
                if attr == 'index':
                    self._assertGreaterEqual(
                        int(a),
                        0,
                        f'The {attr} attribute MUST be >= 0 - TR pag. 20',
                        **error_kwargs
                    )
                elif attr == 'Binding':
                    self._assertIn(
                        a, constants.ALLOWED_BINDINGS,
                        (('The %s attribute MUST be one of [%s] - TR pag. 20') %
                         (attr, ', '.join(constants.ALLOWED_BINDINGS))),
                        **error_kwargs
                    )
                elif attr == 'Location' and self.production:
                    self._assertIsValidHttpsUrl(
                        a,
                        f'The {attr} attribute MUST be a '
                        'valid HTTPS url - TR pag. 20 and AV n. 1',
                        **error_kwargs
                    )
                else:
                    pass

        return self.is_ok(f'{self.__class__.__name__}.test_AssertionConsumerService')

    def test_AssertionConsumerService_SPID(self):
        acss = self.doc.xpath('//EntityDescriptor/SPSSODescriptor'
                              '/AssertionConsumerService'
                              '[@isDefault="true"]')
        desc = [etree.tostring(ent).decode() for ent in acss if acss]
        error_kwargs = dict(description = desc) if desc else {}

        self._assertTrue((len(acss) == 1),
                         'Only one default AssertionConsumerService '
                         'MUST be present - TR pag. 20',
                         **error_kwargs)

        acss = self.doc.xpath('//EntityDescriptor/SPSSODescriptor'
                              '/AssertionConsumerService'
                              '[@index="0"]'
                              '[@isDefault="true"]')
        self._assertTrue((len(acss) == 1),
                         'Must be present the default AssertionConsumerService '
                         'with index = 0 - TR pag. 20',
                         **error_kwargs)
        return self.is_ok(
            f'{self.__class__.__name__}.test_AssertionConsumerService__SPID')

    def test_AttributeConsumingService(self):
        '''Test the compliance of AttributeConsumingService element(s)'''
        acss = self.doc.xpath('//EntityDescriptor/SPSSODescriptor'
                              '/AttributeConsumingService')

        desc = [etree.tostring(ent).decode() for ent in acss if acss]
        error_kwargs = dict(description = desc) if desc else {}

        self._assertGreaterEqual(
            len(acss),
            1,
            'One or more AttributeConsumingService elements MUST be present - TR pag. 20',
            **error_kwargs
        )
        return self.is_ok(f'{self.__class__.__name__}.test_AttributeConsumingService')


    def test_AttributeConsumingService_SPID(self):
        acss = self.doc.xpath('//EntityDescriptor/SPSSODescriptor'
                              '/AttributeConsumingService')

        desc = [etree.tostring(ent).decode() for ent in acss if acss]
        error_kwargs = dict(description = desc) if desc else {}
        for acs in acss:
            self._assertTrue(
                ('index' in acs.attrib),
                'The index attribute in AttributeConsumigService element MUST be present',
                **error_kwargs)

            idx = int(acs.get('index'))
            self._assertGreaterEqual(
                idx,
                0,
                'The index attribute in AttributeConsumigService '
                'element MUST be >= 0 - TR pag. 20',
                **error_kwargs
            )

            sn = acs.xpath('./ServiceName')
            self._assertTrue((len(sn) > 0),
                             'The ServiceName element MUST be present',
                             **error_kwargs)
            for sns in sn:
                self._assertIsNotNone(
                    sns.text,
                    'The ServiceName element MUST have a value',
                    **error_kwargs)

            ras = acs.xpath('./RequestedAttribute')
            self._assertGreaterEqual(
                len(ras),
                1,
                'One or more RequestedAttribute elements MUST be present - TR pag. 20',
                **error_kwargs
            )

            for ra in ras:
                self._assertTrue(
                    ('Name' in ra.attrib),
                    'The Name attribute in RequestedAttribute element '
                    'MUST be present - TR pag. 20 and AV n. 6',
                    **error_kwargs)

                self._assertIn(
                    ra.get('Name'),
                    constants.SPID_ATTRIBUTES,
                    f'The "{ra.attrib.values()[0]}" attribute in RequestedAttribute element MUST be valid',
                    description = f"one of [{', '.join(constants.SPID_ATTRIBUTES)}] - TR pag. 20 and AV n.6"
                )

            al = acs.xpath('RequestedAttribute/@Name')
            self._assertEqual(
                len(al),
                len(set(al)),
                'AttributeConsumigService MUST not contain duplicated RequestedAttribute - TR pag. 20',
                **error_kwargs
            )
        return self.is_ok(f'{self.__class__.__name__}.test_AttributeConsumingService_SPID')

    def test_Organization(self):
        '''Test the compliance of Organization element'''
        orgs = self.doc.xpath('//EntityDescriptor/Organization')

        desc = [etree.tostring(ent).decode() for ent in orgs if orgs]
        error_kwargs = dict(description = desc) if desc else {}

        self._assertTrue(
            (len(orgs) == 1),
            'Only one Organization element can be present - TR pag. 20'
        )

        enames = ['OrganizationName',
                  'OrganizationDisplayName',
                  'OrganizationURL']
        lang_counter = dict()

        if len(orgs) == 1:
            org = orgs[0]
            for ename in enames:
                elements = org.xpath(f'./{ename}')
                self._assertGreater(
                    len(elements),
                    0,
                    f'One or more {ename} elements MUST be present - TR pag. 20',
                    **error_kwargs
                )

                for element in elements:
                    self._assertTrue(
                        ('{http://www.w3.org/XML/1998/namespace}lang' in element.attrib),  # noqa
                        f'The lang attribute in {ename} element MUST be present - TR pag. 20', # noqa
                        **error_kwargs
                    )

                    lang = element.attrib.items()[0][1]
                    if lang_counter.get(lang):
                        lang_counter[lang] += 1
                    else:
                        lang_counter[lang] = 1


                    self._assertIsNotNone(
                        element.text,
                        f'The {ename} element MUST have a value - TR pag. 20',
                        **error_kwargs
                    )

                    if ename == 'OrganizationURL' and self.production:
                        OrganizationURLvalue = element.text.strip()
                        if not (OrganizationURLvalue.startswith('http://') or
                                OrganizationURLvalue.startswith('https://')):
                            OrganizationURLvalue = f'https://{OrganizationURLvalue}'
                        self._assertIsValidHttpUrl(
                            OrganizationURLvalue,
                            f'The {ename} -element MUST be a valid URL - TR pag. 20',
                            **error_kwargs
                        )

            # lang counter check
            for k,v in lang_counter.items():
                num_enames = len(enames)
                self._assertTrue(
                        (v == num_enames),
                        (f'The elements OrganizationName, OrganizationDisplayName and OrganizationURL '
                         'MUST have the same number of lang attributes'), # noqa
                        **error_kwargs
                    )

            self._assertTrue(
                    ("it" in lang_counter),
                    (f'The elements OrganizationName, OrganizationDisplayName and OrganizationURL '
                     'MUST have at least an it language enabled'), # noqa
                    **error_kwargs
                )

        return self.is_ok(f'{self.__class__.__name__}.test_Organization')

    def test_profile_saml2core(self):
        self.xsd_check()

        # loop for all the attrs that starts with test_ ... todo?
        self.test_EntityDescriptor()

        self.test_SPSSODescriptor()
        self.test_NameIDFormat_Transient()
        self.test_xmldsig()
        self.test_Signature()
        self.test_KeyDescriptor()
        self.test_SingleLogoutService()
        self.test_AssertionConsumerService()
        self.test_AttributeConsumingService()
        self.test_Organization()

    def test_profile_spid_sp(self):
        self.test_profile_saml2core()

        self.xsd_check(
            xsds_files = ['saml-schema-metadata-sp-spid.xsd',
                          'saml-schema-metadata-sp-spid-av29.xsd']
        )
        self.test_SPSSODescriptor_SPID()
        self.test_AssertionConsumerService_SPID()
        self.test_AttributeConsumingService_SPID()

    def test_profile_spid_sp_public(self):
        self.test_profile_spid_sp()
        # TODO
        # self.test_ExtensionsContactPersonSPPublic()

    def test_profile_spid_sp_private(self):
        self.test_profile_spid_sp()
        # TODO
        # self.test_ExtensionsContactPersonSPPrivate()

    def test_profile_spid_ag_full(self):
        self.test_profile_spid_sp()
        # TODO
        # self.test_ExtensionsContactPersonAGFull()

    def test_profile_spid_ag_lite(self):
        self.test_profile_spid_sp()
        # TODO
        # self.test_ExtensionsContactPersonAGLite()

    def test_profile_spid_op_full(self):
        self.test_profile_spid_sp()
        # TODO
        # self.test_ExtensionsContactPersonOPFull()
