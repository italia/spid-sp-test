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
from .metadata_public import SpidSpMetadataCheckPublic
from .metadata_private import SpidSpMetadataCheckPrivate
from .metadata_ag import SpidSpMetadataCheckAG

sys.path.append(os.path.join(os.path.dirname(__file__), os.pardir))


logger = logging.getLogger(__name__)


class SpidSpMetadataCheck(
    AbstractSpidCheck,
    SpidSpMetadataCheckPublic,
    SpidSpMetadataCheckPrivate,
    SpidSpMetadataCheckAG,
):
    def __init__(
        self,
        metadata_url,
        xsds_files: list = None,
        xsds_files_path: str = None,
        production: bool = False,
    ):

        super(SpidSpMetadataCheck, self).__init__(verify_ssl=production)
        self.category = "metadata_strict"

        self.logger = logger
        self.metadata_url = metadata_url
        self.production = production
        self.metadata = self.get(metadata_url)
        self.xsds_files_path = xsds_files_path or f"{BASE_DIR}/xsd"

        self.doc = etree.fromstring(self.metadata)
        # clean up namespace (otherwise xpath doesn't work ...)
        del_ns(self.doc)

    def get(self, metadata_url: str):
        if metadata_url[0:7] == "file://":
            return open(metadata_url[7:], "rb").read()
        else:
            request = requests.get(
                metadata_url, allow_redirects=True, verify=self.production
            )
            if request.status_code != 200:
                raise Exception(
                    f"Metadata not found: server response with code {request.status_code}"
                )
            else:
                return request.content

    def xsd_check(self, xsds_files: list = ["saml-schema-metadata-2.0.xsd"]):
        _method = f"{self.__class__.__name__}.xsd_check"
        test_id = ["1.0.0"]
        logger.debug(self.metadata.decode())
        _orig_pos = os.getcwd()
        os.chdir(self.xsds_files_path)
        metadata = self.metadata.decode()
        for testf in xsds_files:
            try:
                schema_file = open(testf, "rb")
                msg = f"Test {self.metadata_url} with {schema_file.name}"
                schema = xmlschema.XMLSchema(schema_file)
                if not schema.is_valid(metadata):
                    schema.validate(metadata)
                    self._assertTrue(
                        False,
                        msg,
                        description=msg,
                        references="",
                        method=_method,
                        test_id=test_id,
                    )
                    # raise Exception('Validation Error')
                break
            except Exception as e:
                os.chdir(_orig_pos)
                logger.error(f"{msg}: {e}")
                self._assertTrue(
                    False,
                    msg,
                    description="xsd test failed",
                    traceback=f"{e}",
                    method=_method,
                    test_id=test_id,
                )
        os.chdir(_orig_pos)
        if not self.errors:
            self._assertTrue(
                True, _method, description=msg, method=_method, test_id=test_id
            )
        return self.is_ok(_method)

    def test_EntityDescriptor(self):
        entity_desc = self.doc.xpath("//EntityDescriptor")
        desc = [
            etree.tostring(ent).decode()[:128] for ent in entity_desc if entity_desc
        ]
        _method = f"{self.__class__.__name__}.test_EntityDescriptor"
        _data = dict(references=["TR pag. 19"], method=_method)

        self._assertTrue(
            len(entity_desc) == 1,
            "Only one EntityDescriptor element MUST be present",
            description=desc,
            test_id=["1.3.0"],
            **_data,
        )

        self._assertTrue(
            self.doc.attrib.get("entityID"),
            "The entityID attribute MUST be present",
            description=self.doc.attrib,
            test_id=["1.3.1"],
            **_data,
        )

        self._assertTrue(
            entity_desc[0].get("entityID"),
            "The entityID attribute MUST have a value",
            description=entity_desc[0].get("entityID"),
            **_data,
            test_id=["1.3.2"],
        )

        if self.production:
            self._assertIsValidHttpsUrl(
                self.doc.attrib.get("entityID"),
                "The entityID attribute MUST be a valid HTTPS url",
                **_data,
            )
            self._assertHttpUrlWithoutPort(
                self.doc.attrib.get("entityID"),
                'The entityID attribute MUST not contains any custom tcp ports, eg: ":8000"',
                **_data,
            )

        return self.is_ok(_method)

    def test_SPSSODescriptor(self):
        spsso = self.doc.xpath("//EntityDescriptor/SPSSODescriptor")
        desc = [etree.tostring(ent).decode()[:128] for ent in spsso if spsso]

        _method = f"{self.__class__.__name__}.test_SPSSODescriptor"
        _data = dict(
            test_id=["1.6.0"], references=[""], method=_method, description=desc
        )

        self._assertTrue(
            (len(spsso) == 1),
            "Only one SPSSODescriptor element MUST be present",
            **_data,
        )
        return self.is_ok(_method)

    def test_SPSSODescriptor_SPID(self):
        spsso = self.doc.xpath("//EntityDescriptor/SPSSODescriptor")
        desc = [etree.tostring(ent).decode()[:128] for ent in spsso if spsso]
        _method = f"{self.__class__.__name__}.test_SPSSODescriptor_SPID"
        _data = dict(references=["TR pag. 20"], method=_method, description=desc)

        if spsso:
            _spsso = spsso[0]
        else:
            self._assertTrue(
                False,
                f"SPSSODescriptor element not found",
                test_id=[""],
                **_data,
            )
            return self.is_ok(_method)

        for attr in ["protocolSupportEnumeration", "AuthnRequestsSigned"]:
            self._assertTrue(
                (attr in _spsso.attrib),
                f"The {attr} attribute MUST be present",
                test_id=["1.6.1", "1.6.3"],
                **_data,
            )

            a = _spsso.get(attr)
            self._assertTrue(
                a,
                f"The {attr} attribute MUST have a value",
                test_id=["1.6.2", "1.6.4"],
                **_data,
            )

            if attr == "AuthnRequestsSigned" and a:
                self._assertTrue(
                    a.lower() == "true",
                    f"The {attr} attribute MUST be true",
                    test_id=["1.6.5"],
                    **_data,
                )

        return self.is_ok(_method)

    def test_NameIDFormat_Transient(self):
        spsso = self.doc.xpath("//EntityDescriptor/SPSSODescriptor/NameIDFormat")
        desc = [etree.tostring(ent).decode() for ent in spsso if spsso]

        _method = f"{self.__class__.__name__}.test_NameIDFormat_Transient"
        _data = dict(
            test_id="", references=["TR pag. ..."], method=_method, description=desc
        )

        if spsso:
            _rule = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
            self._assertTrue(
                (spsso[0].text == _rule),
                f"The NameIDFormat MUST be {_rule}",
                **_data,
            )

        return self.is_ok(_method)

    def test_xmldsig(self):
        """Verify the SP metadata signature"""
        tmp_file = NamedTemporaryFile(suffix=".xml")
        tmp_file.write(self.metadata)
        tmp_file.seek(0)
        xmlsec_cmd = [
            "xmlsec1",
            "--verify",
            "--insecure",
            "--id-attr:ID",
            "urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor",
            tmp_file.name,
        ]
        cmd = " ".join(xmlsec_cmd)
        msg = "the metadata signature MUST be valid"

        _data = dict(
            test_id=["1.9.0"],
            references=["TR pag. 19"],
            method=f"{self.__class__.__name__}.test_xmldsig",
        )

        try:
            subprocess.run(
                cmd,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except subprocess.CalledProcessError as err:
            lines = [msg]
            if err.stderr:
                stderr = "stderr: " + "\nstderr: ".join(
                    list(filter(None, err.stderr.decode("utf-8").split(r"\n")))
                )
                lines.append(stderr)
            if err.stdout:
                stdout = "stdout: " + "\nstdout: ".join(
                    list(filter(None, err.stdout.decode("utf-8").split(r"\n")))
                )
                lines.append(stdout)
            _msg = "\n".join(lines)
            self.handle_result(
                "error", _msg, description="Description", traceback=_msg, **_data
            )
            return

        xmlsec_cmd_string = " ".join(xmlsec_cmd)
        self.handle_result("info", msg, description=f"{xmlsec_cmd_string}", **_data)

    def test_Signature(self):
        """Test the compliance of Signature element"""
        _method = f"{self.__class__.__name__}.test_Signature"
        sign = self.doc.xpath("//EntityDescriptor/Signature")
        desc = [etree.tostring(ent).decode() for ent in sign if sign]

        _data = dict(
            description="".join(desc)[:128] or "",
            references=["TR pag. 19"],
            method=_method,
        )

        self._assertTrue(
            (len(sign) > 0),
            "The Signature element MUST be present",
            test_id=["1.7.0"],
            **_data,
        )

        if not sign:
            self.handle_result(
                "error",
                "The SignatureMethod element MUST be present",
                test_id=["1.7.1"],
                **_data,
            )
            self.handle_result(
                "error",
                "The Algorithm attribute MUST be present in SignatureMethod element",
                test_id=["1.7.2"],
                **_data,
            )
            self.handle_result(
                "error",
                "The Algorithm attribute MUST be present in DigestMethod element",
                test_id=["1.7.4"],
                **_data,
            )

            _data.pop("description")
            self.handle_result(
                "error",
                "The signature algorithm MUST be valid",
                description=f"Must be one of [{', '.join(constants.ALLOWED_XMLDSIG_ALGS)}]",
                test_id=["1.7.3"],
                **_data,
            )

            self.handle_result(
                "error",
                "The digest algorithm MUST be valid",
                description=f"Must be one of [{', '.join(constants.ALLOWED_DGST_ALGS)}]",
                test_id=["1.7.5"],
                **_data,
            )
        else:
            method = sign[0].xpath("./SignedInfo/SignatureMethod")
            desc = [etree.tostring(ent).decode() for ent in method if method]
            _data["description"] = "".join(desc)[:128]
            self._assertTrue(
                (len(method) > 0),
                "The SignatureMethod element MUST be present",
                test_id=["1.7.1"],
                **_data,
            )

            self._assertTrue(
                ("Algorithm" in method[0].attrib),
                "The Algorithm attribute MUST be present " "in SignatureMethod element",
                **_data,
            )

            _data.pop("description")
            alg = method[0].get("Algorithm")
            self._assertTrue(
                alg in constants.ALLOWED_XMLDSIG_ALGS,
                "The signature algorithm MUST be valid",
                description=f"One of {(', '.join(constants.ALLOWED_XMLDSIG_ALGS))}",
                test_id=["1.7.3"],
                **_data,
            )

            method = sign[0].xpath("./SignedInfo/Reference/DigestMethod")
            self._assertTrue(
                (len(method) == 1),
                "The DigestMethod element MUST be present",
                test_id=["1.7.4"],
                **_data,
            )

            self._assertTrue(
                ("Algorithm" in method[0].attrib),
                "The Algorithm attribute MUST be present in DigestMethod element",
                test_id=["1.7.5"],
                **_data,
            )

            alg = method[0].get("Algorithm")
            self._assertTrue(
                alg in constants.ALLOWED_DGST_ALGS,
                "The digest algorithm MUST be valid",
                description=f"One of {(', '.join(constants.ALLOWED_DGST_ALGS))}",
                test_id=["1.7.6"],
                **_data,
            )

        return self.is_ok(_method)

    def test_KeyDescriptor(self):
        """Test the compliance of KeyDescriptor element(s)"""
        _method = f"{self.__class__.__name__}.test_KeyDescriptor"
        kds = self.doc.xpath(
            "//EntityDescriptor/SPSSODescriptor" '/KeyDescriptor[@use="signing"]'
        )
        _data = dict(references=["TR pag. 19"], method=_method)
        self._assertTrue(
            len(kds) >= 1,
            "At least one signing KeyDescriptor MUST be present",
            test_id=["1.4.0"],
            **_data,
        )

        desc = [etree.tostring(ent).decode() for ent in kds if kds]

        for kd in kds:
            certs = kd.xpath("./KeyInfo/X509Data/X509Certificate")
            self._assertTrue(
                len(certs) >= 1,
                "At least one signing x509 MUST be present",
                description="".join(desc)[:128] or "",
                test_id=["1.4.1"],
                **_data,
            )

        kds = self.doc.xpath(
            "//EntityDescriptor/SPSSODescriptor" '/KeyDescriptor[@use="encryption"]'
        )

        for kd in kds:
            certs = kd.xpath("./KeyInfo/X509Data/X509Certificate")
            self._assertTrue(
                len(certs) >= 1,
                "At least one encryption x509 MUST be present",
                test_id=["1.4.2"],
                **_data,
            )

        return self.is_ok(_method)

    def test_SingleLogoutService(self):
        """Test the compliance of SingleLogoutService element(s)"""
        slos = self.doc.xpath(
            "//EntityDescriptor/SPSSODescriptor" "/SingleLogoutService"
        )
        _method = f"{self.__class__.__name__}.test_SingleLogoutService"
        desc = [etree.tostring(ent).decode() for ent in slos if slos]
        _data = dict(
            references=["AV n. 3"],
            method=_method,
            description="".join(desc)[:128],
        )

        self._assertTrue(
            len(slos) >= 1,
            "One or more SingleLogoutService elements MUST be present",
            test_id=["1.8.0"],
            **_data,
        )

        for slo in slos:
            for attr in ["Binding", "Location"]:
                self._assertTrue(
                    (attr in slo.attrib),
                    f"The {attr} attribute in SingleLogoutService element MUST be present",
                    test_id=["1.8.1", "1.8.4"],
                    **_data,
                )

                _attr = slo.get(attr)
                self._assertTrue(
                    _attr,
                    f"The {attr} attribute in SingleLogoutService element MUST have a value",
                    test_id=["1.8.2", "1.8.5"],
                    **_data,
                )

                if attr == "Binding":
                    self._assertTrue(
                        _attr in constants.ALLOWED_SINGLELOGOUT_BINDINGS,
                        (
                            (
                                "The %s attribute in SingleLogoutService element MUST be one of [%s]"
                            )
                            % (attr, ", ".join(constants.ALLOWED_BINDINGS))  # noqa
                        ),
                        test_id=["1.8.3"],
                        **_data,  # noqa
                    )
                if attr == "Location" and self.production:
                    self._assertIsValidHttpsUrl(
                        _attr,
                        f"The {attr} attribute "
                        "in SingleLogoutService element "
                        "MUST be a valid HTTPS URL",
                        test_id=["1.8.6"],
                        **_data,
                    )
                    self._assertHttpUrlWithoutPort(
                        _attr,
                        'The entityID attribute MUST not contain any custom tcp ports, eg: ":8000"',
                        **_data,
                    )
                elif attr == "Location":
                    self._assertIsValidHttpUrl(
                        _attr,
                        f"The {attr} attribute "
                        "in SingleLogoutService element "
                        "MUST be a valid HTTP URL",
                        **_data,
                    )

        return self.is_ok(_method)

    def test_AssertionConsumerService(self):
        """Test the compliance of AssertionConsumerService element(s)"""
        acss = self.doc.xpath(
            "//EntityDescriptor/SPSSODescriptor" "/AssertionConsumerService"
        )
        _method = f"{self.__class__.__name__}.test_AssertionConsumerService"
        desc = [etree.tostring(ent).decode() for ent in acss if acss]
        _data = dict(
            references=["TR pag. 20"],
            method=_method,
            description="".join(desc)[:128],
        )

        self._assertTrue(
            len(acss) >= 1,
            "At least one AssertionConsumerService MUST be present",
            test_id=["1.1.0"],
            **_data,
        )

        for acs in acss:
            for attr in ["index", "Binding", "Location"]:
                self._assertTrue(
                    (attr in acs.attrib),
                    f"The {attr} attribute MUST be present",
                    test_id=["1.1.1", "1.1.3", "1.1.5"],
                    **_data,
                )
                _attr = acs.get(attr)
                if attr == "index":
                    self._assertTrue(
                        int(_attr) >= 0,
                        f"The {attr} attribute MUST be >= 0",
                        test_id=["1.1.2"],
                        **_data,
                    )
                elif attr == "Binding":
                    self._assertTrue(
                        _attr in constants.ALLOWED_BINDINGS,
                        (
                            ("The %s attribute MUST be one of [%s]")
                            % (attr, ", ".join(constants.ALLOWED_BINDINGS))
                        ),
                        test_id=["1.1.4"],
                        **_data,
                    )
                elif attr == "Location" and self.production:
                    self._assertIsValidHttpsUrl(
                        _attr,
                        f"The {attr} attribute MUST be a valid HTTPS url",
                        test_id=["1.1.6"],
                        **_data,
                    )
                    self._assertHttpUrlWithoutPort(
                        _attr,
                        'The entityID attribute MUST not contain any custom tcp ports, eg: ":8000"',
                        test_id=["1.1.6"],
                        **_data,
                    )
                else:
                    pass

        return self.is_ok(_method)

    def test_AssertionConsumerService_SPID(self):
        acss = self.doc.xpath(
            "//EntityDescriptor/SPSSODescriptor"
            "/AssertionConsumerService"
            '[@isDefault="true"]'
        )
        _method = f"{self.__class__.__name__}.test_AssertionConsumerService_SPID"
        desc = [etree.tostring(ent).decode() for ent in acss if acss]
        _data = dict(
            references=["TR pag. 20"],
            method=_method,
            description="".join(desc)[:128],
        )

        self._assertTrue(
            (len(acss) == 1),
            "Only one default AssertionConsumerService MUST be present",
            test_id=["1.1.7"],
            **_data,
        )

        acss = self.doc.xpath(
            "//EntityDescriptor/SPSSODescriptor"
            "/AssertionConsumerService"
            '[@index="0"]'
            '[@isDefault="true"]'
        )
        self._assertTrue(
            (len(acss) == 1),
            "Must be present the default AssertionConsumerService with index = 0",
            test_id=["1.1.8"],
            **_data,
        )
        return self.is_ok(_method)

    def test_AttributeConsumingService(self):
        """Test the compliance of AttributeConsumingService element(s)"""
        acss = self.doc.xpath(
            "//EntityDescriptor/SPSSODescriptor" "/AttributeConsumingService"
        )
        _method = f"{self.__class__.__name__}.test_AttributeConsumingService"
        desc = [etree.tostring(ent).decode() for ent in acss if acss]
        _data = dict(
            references=["TR pag. 20"],
            method=_method,
            description="".join(desc)[:128],
        )

        self._assertTrue(
            len(acss) >= 1,
            "One or more AttributeConsumingService elements MUST be present",
            test_id=["1.2.0"],
            **_data,
        )
        return self.is_ok(_method)

    def test_AttributeConsumingService_SPID(
        self, allowed_attributes=constants.SPID_ATTRIBUTES
    ):
        acss = self.doc.xpath(
            "//EntityDescriptor/SPSSODescriptor/AttributeConsumingService"
        )
        desc = [etree.tostring(ent).decode() for ent in acss if acss]
        _method = f"{self.__class__.__name__}.test_AttributeConsumingService_SPID"
        _data = dict(
            references=["TR pag. 20"],
            method=_method,
        )
        _desc = "".join(desc)[:128]
        for acs in acss:
            self._assertTrue(
                ("index" in acs.attrib),
                "The index attribute in AttributeConsumigService element MUST be present",
                description=_desc,
                test_id=["1.2.1"],
                **_data,
            )

            idx = int(acs.get("index"))
            self._assertTrue(
                idx >= 0,
                "The index attribute in AttributeConsumigService element MUST be >= 0",
                description=_desc,
                test_id=["1.2.2"],
                **_data,
            )

            sn = acs.xpath("./ServiceName")
            self._assertTrue(
                (len(sn) > 0),
                "The ServiceName element MUST be present",
                description=_desc,
                test_id=["1.2.3"],
                **_data,
            )
            for sns in sn:
                self._assertTrue(
                    sns.text,
                    "The ServiceName element MUST have a value",
                    description=_desc,
                    test_id=["1.2.4"],
                    **_data,
                )

            ras = acs.xpath("./RequestedAttribute")
            self._assertTrue(
                len(ras) >= 1,
                "One or more RequestedAttribute elements MUST be present",
                description=_desc,
                test_id=["1.2.5"],
                **_data,
            )

            for ra in ras:
                self._assertTrue(
                    ("Name" in ra.attrib),
                    "The Name attribute in RequestedAttribute element "
                    "MUST be present",
                    test_id=["1.2.6"],
                    description=_desc,
                    **_data,
                )

                self._assertTrue(
                    ra.get("Name") in allowed_attributes,
                    f'The "{ra.attrib.values()[0]}" attribute in RequestedAttribute element MUST be valid',
                    description=f"one of [{', '.join(allowed_attributes)}]",
                    **_data,
                    test_id=["1.2.7"],
                )

            al = acs.xpath("RequestedAttribute/@Name")
            self._assertTrue(
                len(al) == len(set(al)),
                "AttributeConsumigService MUST not contain duplicated RequestedAttribute",
                description=_desc,
                **_data,
            )
        return self.is_ok(_method)

    def test_Organization(self):
        """Test the compliance of Organization element"""
        orgs = self.doc.xpath("//EntityDescriptor/Organization")

        desc = [etree.tostring(ent).decode() for ent in orgs if orgs]
        _method = f"{self.__class__.__name__}.test_Organization"
        _data = dict(description=desc, references=["TR pag. 20"], method=_method)

        self._assertTrue(
            (len(orgs) == 1),
            "Only one Organization element can be present",
            test_id=["1.5.0"],
            **_data,
        )

        enames = ["OrganizationName", "OrganizationDisplayName", "OrganizationURL"]
        lang_counter = dict()

        if len(orgs) == 1:
            org = orgs[0]
            for ename in enames:
                elements = org.xpath(f"./{ename}")
                self._assertTrue(
                    len(elements) > 0,
                    f"One or more {ename} elements MUST be present",
                    test_id=["1.5.1", "1.5.4"],
                    **_data,
                )

                for element in elements:
                    self._assertTrue(
                        (
                            "{http://www.w3.org/XML/1998/namespace}lang"
                            in element.attrib
                        ),  # noqa
                        f"The lang attribute in {ename} element MUST be present",  # noqa
                        test_id=["1.5.2", "1.5.5", "1.5.8"],
                        **_data,
                    )

                    lang = element.attrib.items()[0][1]
                    if lang_counter.get(lang):
                        lang_counter[lang] += 1
                    else:
                        lang_counter[lang] = 1

                    self._assertTrue(
                        element.text,
                        f"The {ename} element MUST have a value",
                        test_id=["1.5.3", "1.5.7", "1.5.9"],
                        **_data,
                    )

                    if ename == "OrganizationURL" and self.production:
                        OrganizationURLvalue = element.text.strip()
                        if not (
                            OrganizationURLvalue.startswith("http://")
                            or OrganizationURLvalue.startswith("https://")
                        ):
                            OrganizationURLvalue = f"https://{OrganizationURLvalue}"
                        self._assertIsValidHttpUrl(
                            OrganizationURLvalue,
                            f"The {ename} element MUST be a valid URL",
                            test_id=["1.5.10"],
                            **_data,
                        )

            # lang counter check
            for k, v in lang_counter.items():
                num_enames = len(enames)
                self._assertTrue(
                    (v == num_enames),
                    (
                        "The elements OrganizationName, OrganizationDisplayName and OrganizationURL "
                        "MUST have the same number of lang attributes"
                    ),  # noqa
                    test_id=["1.5.5", "1.5.8"],
                    **_data,
                )

            self._assertTrue(
                ("it" in lang_counter),
                (
                    "The elements OrganizationName, OrganizationDisplayName and OrganizationURL "
                    "MUST have at least an it language enabled"
                ),  # noqa
                **_data,
            )

        return self.is_ok(_method)

    def test_profile_saml2core(self):
        self.xsd_check(xsds_files=["saml-schema-metadata-2.0.xsd"])

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
            xsds_files=[
                "saml-schema-metadata-sp-spid.xsd",
                "saml-schema-metadata-sp-spid-av29.xsd",
            ]
        )
        self.test_SPSSODescriptor_SPID()
        self.test_AssertionConsumerService_SPID()
        self.test_AttributeConsumingService_SPID()
        self.test_contactperson_email()
        self.test_contactperson_phone()

    def test_profile_spid_sp_public(self):
        self.test_profile_spid_sp()
        self.test_Contacts_PubPriv()
        self.test_Extensions_PubPriv()
        self.test_Contacts_VATFC()
        self.test_Contacts_IPACode()
        self.test_extensions_public_private(ext_type="Public")

    def test_profile_spid_sp_private(self):
        self.test_profile_spid_sp()
        self.test_Contacts_PubPriv()
        self.test_Contacts_PubPriv(contact_type="billing")
        self.test_Extensions_PubPriv()
        self.test_extensions_public_private(ext_type="Private")

        # invalid ! to be removed soon
        # self.test_contactperson_email(
        # email_xpath="//ContactPerson/Extensions/CessionarioCommittente/EmailAddress"
        # )

        self.test_Contacts_VATFC(private=True)
        self.test_Contacts_Priv()
        self.xsd_check(
            xsds_files=["saml-schema-metadata-2.0.xsd", "spid-invoicing.xsd"]
        )

    def test_profile_spid_sp_ag_public_full(self):
        self.test_profile_spid_sp()

        self.test_extensions_public_private(ext_type="Public")
        self.test_Contacts_IPACode()
        self.test_Contacts_VATFC()
        self.test_extensions_public_ag()
        self.test_Extensions_PubPriv()

        # The ContactPerson element of contactType “other” and spid:entityType “spid:aggregator” MUST be present
        # The ContactPerson element of contactType “other” and spid:entityType “spid:aggregated” MUST be present
        self.test_Contacts_PubPriv(entity_type="spid:aggregator")
        self.test_Contacts_PubPriv(entity_type="spid:aggregated")

        # The entityID MUST not contain the query-string part
        self.test_entityid_qs()

        # The entityID MUST contain the activity code “pub-ag-full”
        self.test_entityid_contains(value="pub-ag-full")

        # The PublicServicesFullAggregator element MUST be present
        self.test_extensions_public_ag(
            ext_types=["//ContactPerson/Extensions/PublicServicesFullAggregator"],
            must=True,
        )

    def test_profile_spid_sp_ag_public_lite(self):
        self.test_profile_spid_sp()
        self.test_extensions_public_private(ext_type="Public")

        # The entityID MUST contain the activity code “pub-ag-lite”
        self.test_entityid_contains(value="pub-ag-lite")

        # Only one ContactPerson element of contactType “other” and spid:entityType “spid:aggregator” MUST be present
        # Only one ContactPerson element of contactType “other” and spid:entityType “spid:aggregated” MUST be present
        self.test_Contacts_PubPriv(entity_type="spid:aggregator")
        self.test_Contacts_PubPriv(entity_type="spid:aggregated")

        # TODO
        # If the ContactPerson is of spid:entityType “spid:aggregator”
        # the Extensions element MUST contain the element spid:KeyDescriptor
        # with attribute use “spid:validation”

        # The PublicServicesLightAggregator element MUST be present
        self.test_extensions_public_ag(
            ext_types=["//ContactPerson/Extensions/PublicServicesLightAggregator"],
            must=True,
        )

    def test_profile_spid_sp_op_public_full(self):
        self.test_profile_spid_sp()

        self.test_Contacts_VATFC()

        # The entityID MUST contain the activity code “pub-op-full”
        self.test_entityid_contains(value="pub-op-full")

        # Only one ContactPerson element of contactType “other” and spid:entityType “spid:aggregator” MUST be present
        self.test_Contacts_PubPriv(entity_type="spid:aggregator")

        # The PublicServicesFullOperator element MUST be present
        self.test_extensions_public_ag(
            ext_types=["//ContactPerson/Extensions/PublicServicesFullOperator"],
            must=True,
        )

    def test_profile_spid_sp_op_public_lite(self):
        self.test_profile_spid_sp()

        self.test_Contacts_VATFC()
        self.test_extensions_public_private(ext_type="Public")

        # The entityID MUST contain the activity code “pub-op-lite”
        self.test_entityid_contains(value="pub-op-lite")

        # Only one ContactPerson element of contactType “other” and spid:entityType “spid:aggregator” MUST be present
        # Only one ContactPerson element of contactType “other” and spid:entityType “spid:aggregated” MUST be present
        self.test_Contacts_PubPriv(entity_type="spid:aggregator")
        self.test_Contacts_PubPriv(entity_type="spid:aggregated")

        # The PublicServicesLightOperator element MUST be present
        self.test_extensions_public_ag(
            ext_types=["//ContactPerson/Extensions/PublicServicesLightOperator"],
            must=True,
        )

    def test_profile_cie_sp(self):
        self.test_profile_saml2core()
        self.test_SPSSODescriptor_SPID()
        self.test_contactperson_email()
        self.test_AttributeConsumingService_SPID(
            allowed_attributes=constants.CIE_ATTRIBUTES
        )
        # TODO: ask the validation xsd to IPZS :)
        # self.xsd_check(xsds_files = [

    def test_profile_cie_sp_public(self):
        self.test_profile_cie_sp()
        self.test_extensions_public_private(
            ext_type="Public", contact_type="administrative"
        )
        self.test_Contacts_PubPriv(contact_type="administrative")
        self.test_extensions_cie(ext_type="Public")

    def test_profile_cie_sp_private(self):
        self.test_profile_cie_sp()
        self.test_extensions_public_private(
            ext_type="Private", contact_type="technical"
        )
        self.test_Contacts_PubPriv(contact_type="administrative")
        self.test_Contacts_PubPriv(contact_type="technical")
        self.test_extensions_cie(ext_type="Private")
