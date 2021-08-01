import re

from lxml import etree

from .constants import EMAIL_REGEXP
from .constants import ISO3166_CODES
from .constants import XML_NAMESPACES
from .indicepa import get_indicepa_by_ipacode


class SpidSpMetadataCheckPublic(object):
    def test_Contacts_PubPriv(self, contact_type="other", entity_type=""):
        _method = f"{self.__class__.__name__}.test_Contacts_PubPriv"
        xpatt = f"//ContactPerson[@contactType='{contact_type}'"
        if entity_type:
            xpatt += f" and @spid:entityType='{entity_type}']"
        else:
            xpatt += "]"

        _data = dict(references=["TR pag. 19"], method=_method)
        entity_desc = self.doc.xpath(xpatt, namespaces=XML_NAMESPACES)
        self._assertTrue(entity_desc, "ContactPerson MUST be present", **_data)

        if entity_desc:
            self._assertTrue(
                entity_desc[0].attrib.get("contactType"),
                (
                    f"Missing contactType in {entity_desc[0].attrib}: "
                    "The contactType attribute MUST be present",
                ),
                **_data,
            )
            self._assertTrue(
                entity_desc[0].get("contactType"),
                "The contactType attribute MUST have a value",
                **_data,
            )
            self._assertTrue(
                entity_desc[0].get("contactType") == contact_type,
                f'The contactType must be "{contact_type}"',
                description=entity_desc[0].get("contactType"),
                **_data,
            )

        if not entity_type:
            self._assertTrue(
                len(entity_desc) == 1,
                "Only one ContactPerson element of contactType "
                f'"{contact_type}" MUST be present',
                test_id = ['1.10.0'], **_data,
            )

        return self.is_ok(_method)

    def test_Extensions_PubPriv(self):
        _conts = self.doc.xpath("//ContactPerson")
        _method = f"{self.__class__.__name__}.test_Extensions_PubPriv"
        _data = dict(references=[""], method=_method)
        for cont in _conts:
            ext_cnt = 0
            for child in cont.getchildren():
                if child.tag == "Extension":
                    ext_cnt += 1

            self._assertFalse(
                ext_cnt > 1,
                "Only one Extensions element inside ContactPerson element MUST be present",
                description=etree.tostring(cont).decode(),
                test_id = ['1.10.1'], **_data,
            )

        orgs = self.doc.xpath("//EntityDescriptor/Organization/OrganizationName")
        if len(orgs) >= 1:
            org = orgs[0]
            company = self.doc.xpath("//ContactPerson/CompanyName")
            if company:
                company = company[0]

                self._assertTrue(
                    company.text,
                    "If the Company element is present it MUST have a value",
                    description=company,
                    **_data,
                )

                self._assertTrue(
                    company.text == org.text,
                    "If the Company element if present it MUST be equal to OrganizationName",
                    description=(company.text, org.text),
                    test_id = ['1.10.3'], **_data,
                )

        return self.is_ok(_method)

    def test_contactperson_email(self, email_xpath="//ContactPerson/EmailAddress"):
        _method = f"{self.__class__.__name__}.test_contactperson_email"
        _data = dict(references=[""], method=_method)
        email = self.doc.xpath(email_xpath)
        self._assertTrue(
            email,
            f"The {email_xpath} element MUST be present",
            description=[etree.tostring(_val).decode() for _val in email],
            test_id = ['1.10.4'], **_data,
        )
        if email:
            self._assertTrue(
                email[0].text,
                f"The {email_xpath} element MUST have a value",
                description=[etree.tostring(_val).decode() for _val in email],
                test_id = ['1.10.5'], **_data,
            )
            self._assertTrue(
                re.match(EMAIL_REGEXP, email[0].text),
                f"The {email_xpath} element MUST be a valid email address",
                description=[etree.tostring(_val).decode() for _val in email],
                test_id = ['1.10.6'], **_data,
            )
        return self.is_ok(_method)

    def test_contactperson_phone(self, phone_xpath="//ContactPerson/TelephoneNumber"):
        _method = f"{self.__class__.__name__}.test_contactperson_phone"
        _data = dict(references=[""], method=_method)
        phone = self.doc.xpath(phone_xpath)
        if phone:
            phone = phone[0].text
            self._assertTrue(
                phone, f"The {phone_xpath} element MUST have a value",
                **_data
            )
            self._assertTrue(
                (" " not in phone),
                f"The {phone_xpath} element MUST not contain spaces",
                description=phone,
                test_id = ['1.10.8'], **_data,
            )
            self._assertTrue(
                (phone[0:3] == "+39"),
                f'The {phone_xpath} element MUST start with "+39"',
                description=phone,
                level="warning",
                test_id = ['1.10.9'], **_data,
            )

        return self.is_ok(_method)

    def test_Contacts_IPACode(self):
        self.doc.xpath("//ContactPerson")
        _method = f"{self.__class__.__name__}.test_Contacts_IPACode"
        _data = dict(references=[""], method=_method)
        if self.production:
            ipacode = self.doc.xpath("//ContactPerson/Extensions/IPACode")
            self._assertTrue(
                ipacode, "The IPACode element MUST be present",
                test_id = ['1.11.0'], **_data
            )
            if ipacode:
                ipacode = ipacode[0]
                self._assertTrue(
                    ipacode.text, "The IPACode element MUST have a value",
                    test_id = ['1.11.1'], **_data
                )
                self._assertTrue(
                    get_indicepa_by_ipacode(ipacode.text)[0] == 1,
                    "The IPACode element MUST have a valid value present on IPA",
                    test_id = ['1.11.2'], **_data,
                )

        return self.is_ok(_method)

    def test_extensions_public_private(self, ext_type="Public", contact_type="other"):
        ext_type_not = "Private" if ext_type == "Public" else "Public"
        _method = f"{self.__class__.__name__}.test_extensions_public_private"
        _data = dict(references=[""], method=_method)
        # only if other, billing doesn't have any Private element in it!
        ctype = self.doc.xpath(
            f'//ContactPerson[@contactType="{contact_type}"]/Extensions/{ext_type.title()}'
        )
        self._assertTrue(
            ctype,
            f"Missing ContactPerson/Extensions/{ext_type.title()}, "
            "this element MUST be present",
            test_id = ['1.11.7', '1.12.5'], **_data,
        )
        if ctype:
            self._assertFalse(
                ctype[0].text, f"The {ext_type.title()} element MUST be empty",
                test_id = ['1.11.8', '1.12.6'], **_data
            )

        ctype = self.doc.xpath(f"//ContactPerson/Extensions/{ext_type_not.title()}")
        self._assertFalse(
            ctype, f"The {ext_type_not.title()} element MUST not be present",
            test_id = ['1.11.9', '1.12.7'], **_data
        )
        return self.is_ok(_method)

    def test_Contacts_VATFC(self, private=False):
        self.doc.xpath("//ContactPerson")
        _method = f"{self.__class__.__name__}.test_Contacts_VATFC"
        _data = dict(references=[""], method=_method)
        vats = self.doc.xpath("//ContactPerson/Extensions/VATNumber")
        self._assertTrue(
            (len(vats) <= 1),
            "only one VATNumber element must be present",
            description=[etree.tostring(_vats).decode() for _vats in vats],
            **_data,
        )
        if vats:
            self._assertTrue(
                vats[0].text, "The VATNumber element MUST have a value",
                test_id = ['1.11.4'], **_data
            )
            self._assertTrue(
                (vats[0].text[:2] in ISO3166_CODES),
                "The VATNumber element MUST start with a valid ISO3166 Code",
                **_data,
            )

        fcs = self.doc.xpath("//ContactPerson/Extensions/FiscalCode")
        if fcs:
            self._assertTrue(
                (len(fcs) == 1),
                "only one FiscalCode element must be present",
                description=[etree.tostring(_fcs).decode() for _fcs in fcs],
                **_data,
            )
            fc = fcs[0]
            self._assertTrue(
                fc.text, "The FiscalCode element MUST have a value",
                test_id = ['1.11.6'], **_data
            )
        if private and not len(fcs) and not len(vats):
            self._assertTrue(
                False,
                "If the VATNumber is not present, the FiscalCode element MUST be present",
                **_data,
            )

        return self.is_ok(_method)

    def test_extensions_cie(self, ext_type="Public"):
        _method = f"{self.__class__.__name__}.test_extensions_cie"
        _data = dict(references=[""], method=_method)
        attrs = ["Municipality"]

        if ext_type == "Private":
            attrs.extend(["VATNumber", "NACE2Code", "FiscalCode"])
        else:
            attrs.extend(
                [
                    "IPACode",
                ]
            )

        # the following elements MUST be present
        contacts = self.doc.xpath("//ContactPerson")
        for contact in contacts:
            for ele in attrs:
                ctype = contact.xpath(f"Extensions/{ele}")

                # some special conditions ...
                if contact.attrib["contactType"] == "technical" and ele == "IPACode":
                    continue

                self._assertTrue(ctype, f"{ele} element MUST be present", **_data)

                # is <= because already protected with the previous check
                self._assertTrue(
                    (len(ctype) <= 1),
                    f"only one {ele} element MUST be present",
                    **_data,
                )

                if ctype:
                    self._assertTrue(
                        ctype[0].text, f"The {ele} element MUST have a value", **_data
                    )

        return self.is_ok(_method)
