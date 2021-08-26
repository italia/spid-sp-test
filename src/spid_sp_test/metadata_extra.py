import datetime
import os
import re

from lxml import etree
from spid_sp_test import constants
from spid_sp_test.dump_pem import dump_metadata_pem
from spid_sp_test.utils import parse_pem

from .metadata import SpidSpMetadataCheck


class SpidSpMetadataCheckExtra(SpidSpMetadataCheck):
    def __init__(self, *args, **kwargs):

        super(SpidSpMetadataCheckExtra, self).__init__(*args, **kwargs)
        self.category = "metadata_extra"

    def test_metadata_no_newlines(self):
        _method = f"{self.__class__.__name__}.test_metadata_no_newlines"
        _data = dict(
            test_id="",
            references=[],
            method=_method,
        )
        self._assertFalse(
            re.match(r"^[\t\n\s\r\ ]*", self.metadata),
            ("The XML of metadata should not " "contains newlines at the beginning."),
            description=self.metadata[0:10],
            level="warning",
            **_data,
        )
        return self.is_ok(_method)

    def test_entityid_match_url(self):
        _method = f"{self.__class__.__name__}.test_entityid_match_url"
        _data = dict(
            test_id="",
            references=[],
            method=_method,
        )
        self._assertTrue(
            (self.doc.attrib.get("entityID") == self.metadata_url),
            f"The EntityID SHOULD be equal to {self.metadata_url}",
            description=f"{self.doc.attrib.get('entityID')}",
            level="warning",
            **_data,
        )
        return self.is_ok(_method)

    def test_Signature_extra(self):
        """Test the compliance of AuthnRequest element"""
        sign = self.doc.xpath("//EntityDescriptor/Signature")

        desc = [etree.tostring(ent).decode() for ent in sign if sign]

        _method = f"{self.__class__.__name__}.test_Signature_extra"
        _data = dict(
            test_id="", references=[], method=_method, description="".join(desc)[:128]
        )

        for si in sign:
            certs = si.xpath("./KeyInfo/X509Data/X509Certificate")

            for i in range(len(certs)):
                cert = certs[i]
                fname = dump_metadata_pem(cert, "sp", "signature", "/tmp")

                sign_cert = parse_pem(fname)
                self._assertFalse(
                    sign_cert[0].lower().startswith("sha1"),
                    (
                        (
                            f"The certificate #{i} MUST not use "
                            f"weak signature algorithm: {sign_cert[0].lower()}"
                        )
                    ),
                    **_data,
                )

                exp = ["rsaEncryption", "id-ecPublicKey"]
                self._assertTrue(
                    sign_cert[2] in exp,
                    (
                        (
                            f"The key type of certificate #{i} MUST be one of [%s] - TR pag. 19"
                        )
                        % (", ".join(exp))
                    ),
                    **_data,
                )

                if sign_cert[2] == "rsaEncryption":
                    exp = constants.MINIMUM_CERTIFICATE_LENGHT
                elif sign_cert[2] == "id-ecPublicKey":
                    exp = 256
                else:
                    pass

                self._assertTrue(
                    (int(sign_cert[1]) >= exp),
                    f"The key length of certificate #{i} MUST be >= {exp}. Instead it is {sign_cert[1]}",
                    **_data,
                )

                self._assertTrue(
                    (
                        datetime.datetime.strptime(sign_cert[3], "%b %d %H:%M:%S %Y")
                        >= datetime.datetime.now()
                    ),
                    f"The certificate #{i} is expired. It was valid till {sign_cert[3]}",
                    **_data,
                )
                os.remove(fname)

        return self.is_ok(_method)

    def test_SPSSODescriptor_extra(self):
        spsso = self.doc.xpath("//EntityDescriptor/SPSSODescriptor")

        _method = f"{self.__class__.__name__}.test_SPSSODescriptor_extra"
        _data = dict(
            references=[],
            method=_method,
        )

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

        for attr in ["protocolSupportEnumeration", "WantAssertionsSigned"]:
            self._assertTrue(
                (attr in spsso[0].attrib),
                f"The {attr} attribute MUST be present",
                description=spsso[0].attrib,
                test_id=["1.6.1", "1.6.7"],
                **_data,
            )

            if attr == "protocolSupportEnumeration":
                a = spsso[0].get(attr)
                self._assertTrue(
                    a, f"The {attr} attribute MUST have a value", description=a, **_data
                )

                self._assertTrue(
                    a == "urn:oasis:names:tc:SAML:2.0:protocol",
                    f"The {attr} attribute MUST be "
                    "urn:oasis:names:tc:SAML:2.0:protocol",
                    description=a,
                    test_id=["1.6.6"],
                    **_data,
                )

            if attr == "WantAssertionsSigned":
                a = spsso[0].get(attr)
                self._assertTrue(
                    a,
                    f"The {attr} attribute MUST have a value",
                    description=a,
                    **_data,
                    test_id=["1.6.8"],
                )

                if a:
                    self._assertTrue(
                        a.lower() == "true",
                        f"The {attr} attribute MUST be true",
                        description=a,
                        test_id=["1.6.9"],
                        **_data,
                    )
        return self.is_ok(_method)

    def test_AttributeConsumingService_extra(self):
        acss = self.doc.xpath(
            "//EntityDescriptor/SPSSODescriptor" "/AssertionConsumerService"
        )

        desc = [etree.tostring(ent).decode() for ent in acss if acss]
        _method = f"{self.__class__.__name__}.test_AttributeConsumingService_extra"
        _data = dict(
            test_id="", references=[], method=_method, description="".join(desc)[:128]
        )

        for acs in acss:
            ras = acs.xpath("./RequestedAttribute")
            for ra in ras:
                a = ra.get("NameFormat")
                if a is not None:
                    self._assertTrue(
                        a in constants.ALLOWED_FORMATS,
                        (
                            (
                                "The NameFormat attribute "
                                "in RequestedAttribute element "
                                "MUST be one of [%s]"
                            )
                            % (", ".join(constants.ALLOWED_FORMATS))
                        ),
                        **_data,
                    )
        return self.is_ok(_method)

    def test_Organization_extra(self):
        orgs = self.doc.xpath("//EntityDescriptor/Organization")
        desc = [etree.tostring(ent).decode() for ent in orgs if orgs]
        _method = f"{self.__class__.__name__}.test_Organization_extra"
        _data = dict(
            test_id="", references=[], method=_method, description="".join(desc)[:128]
        )

        self._assertTrue((len(orgs) == 1), "An Organization MUST be present", **_data)

        if orgs:
            org = orgs[0]
            for elem in ["Name", "URL", "DisplayName"]:
                e = org.xpath(
                    './Organization%s[@xml:lang="it"]' % elem,
                    namespaces={
                        "xml": "http://www.w3.org/XML/1998/namespace",
                    },
                )
                self._assertTrue(
                    (len(e) == 1),
                    f"An IT localised Organization {elem} MUST be present",
                    **_data,
                )
            return self.is_ok(_method)

    def test_profile_spid_sp(self):
        super().test_profile_spid_sp()

        self.test_Signature_extra()
        self.test_AttributeConsumingService_extra()
        self.test_SPSSODescriptor_extra()
        self.test_Organization_extra()
