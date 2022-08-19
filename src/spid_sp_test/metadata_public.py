import re

from lxml import etree

from .constants import EMAIL_REGEXP
from .constants import ISO3166_CODES
from .constants import XML_NAMESPACES
from .indicepa import get_indicepa_by_ipacode


def compose_contact_type_entity_type(
    contact_type: str = "other", entity_type: str = None
):
    xpatt = f"//ContactPerson[@contactType='{contact_type}'"
    if entity_type:
        xpatt += f" and @spid:entityType='{entity_type}'"
    xpatt += "]"
    return xpatt


class SpidSpMetadataCheckPublic(object):
    def test_Contacts_PubPriv(
        self, contact_type: str = "other", entity_type: str = None
    ):
        _method = f"{self.__class__.__name__}.test_Contacts_PubPriv"
        _data = dict(references=["TR pag. 19"], method=_method)

        xpatt = compose_contact_type_entity_type(contact_type, entity_type)
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

        self._assertTrue(
            len(entity_desc) == 1,
            "Only one ContactPerson element of contactType "
            f'"{contact_type}" MUST be present',
            test_id=["01.10.0", "01.13.0", "01.17.00", "01.17.01"],
            **_data,
        )

        return self.is_ok(_method)

    def test_Extensions_PubPriv(
        self, contact_type: str = "other", entity_type: str = None, org_chk=True
    ):
        _method = f"{self.__class__.__name__}.test_Extensions_PubPriv"
        _data = dict(references=[""], method=_method)

        xpatt = compose_contact_type_entity_type(contact_type, entity_type)
        _conts = self.doc.xpath(xpatt, namespaces=XML_NAMESPACES)

        for cont in _conts:
            ext_cnt = 0
            for child in cont.getchildren():
                if child.tag == "Extension":
                    ext_cnt += 1

            self._assertFalse(
                ext_cnt > 1,
                "Only one Extensions element inside ContactPerson element MUST be present",
                description=etree.tostring(cont).decode(),
                test_id=[
                    "01.10.01",
                    "01.13.01",
                    "01.17.02",
                ],
                **_data,
            )

        orgs = self.doc.xpath("//EntityDescriptor/Organization/OrganizationName")
        if len(orgs) >= 1:
            org = orgs[0]
            company = self.doc.xpath(f"{xpatt}/Company", namespaces=XML_NAMESPACES)
            if company:
                company = company[0]
                self._assertTrue(
                    company.text,
                    "If the Company element is present it MUST have a value",
                    description=company,
                    test_id=["01.10.02", "01.13.03", "01.17.04"],
                    **_data,
                )

                if org_chk:
                    self._assertTrue(
                        company.text == org.text,
                        f"If the Company ->{company.text}<- element is present it MUST be equal to OrganizationName ->{org.text}<-",
                        description=(company.text, org.text),
                        test_id=["1.10.3", "01.17.05"],
                        **_data,
                    )
            else:
                self._assertFalse(
                    entity_type == "spid:aggregator"
                    or entity_type == "spid:aggregated",
                    f"The Company element MUST be present {entity_type}",
                    test_id=["01.17.03"],
                    **_data,
                )

        return self.is_ok(_method)

    def test_contactperson_email(
        self, contact_type: str = "other", entity_type: str = None
    ):
        _method = f"{self.__class__.__name__}.test_contactperson_email"
        _data = dict(references=[""], method=_method)

        xpatt = compose_contact_type_entity_type(contact_type, entity_type)
        email_xpath = f"{xpatt}/EmailAddress"
        email = self.doc.xpath(f"{xpatt}/EmailAddress", namespaces=XML_NAMESPACES)

        if email and len(email) > 0 and email[0].text:
            self._assertTrue(
                email[0].text,
                f"The {email_xpath} element MUST have a value",
                description=[etree.tostring(_val).decode() for _val in email],
                test_id=["01.10.05", "01.13.05", "01.17.07"],
                **_data,
            )
            self._assertTrue(
                re.match(EMAIL_REGEXP, email[0].text),
                f"The {email_xpath} element MUST be a valid email address",
                description=[etree.tostring(_val).decode() for _val in email],
                test_id=["01.10.06", "01.13.06", "01.17.08"],
                **_data,
            )
        else:
            self._assertFalse(
                entity_type != "spid:aggregated",
                f"The {email_xpath} element MUST be present",
                description=[etree.tostring(_val).decode() for _val in email],
                test_id=["01.10.04", "01.13.04", "01.17.06"],
                **_data,
            )

        return self.is_ok(_method)

    def test_contactperson_phone(
        self, contact_type: str = "other", entity_type: str = None
    ):
        _method = f"{self.__class__.__name__}.test_contactperson_phone"
        _data = dict(references=[""], method=_method)

        xpatt = compose_contact_type_entity_type(contact_type, entity_type)
        phone_xpath = f"{xpatt}/TelephoneNumber"
        phone = self.doc.xpath(f"{xpatt}/TelephoneNumber", namespaces=XML_NAMESPACES)

        if phone and len(phone) > 0 and phone[0].text:
            phone = phone[0].text
            self._assertTrue(
                phone,
                f"The {phone_xpath} element MUST have a value",
                description=phone,
                test_id=["01.10.07", "01.17.09"],
                **_data,
            )
            self._assertTrue(
                (" " not in phone),
                f"The {phone_xpath} element MUST not contain spaces",
                description=phone,
                test_id=["01.10.08", "01.17.10"],
                **_data,
            )
            self._assertTrue(
                (phone[0:3] == "+39"),
                f'The {phone_xpath} element MUST start with "+39"',
                description=phone,
                level="warning",
                test_id=["01.10.09", "01.17.11"],
                **_data,
            )

        return self.is_ok(_method)

    def test_Contacts_IPACode(
        self,
        contact_type: str = "other",
        entity_type: str = None,
        public=False,
        private=False,
    ):
        _method = f"{self.__class__.__name__}.test_Contacts_IPACode"
        _data = dict(references=[""], method=_method)

        xpatt = compose_contact_type_entity_type(contact_type, entity_type)
        ipacode = self.doc.xpath(
            f"{xpatt}/Extensions/IPACode", namespaces=XML_NAMESPACES
        )
        if self.production:
            if ipacode:
                ipacode = ipacode[0]
                self._assertTrue(
                    ipacode.text,
                    "The IPACode element MUST have a value",
                    test_id=["01.11.03", "01.17.13"],
                    **_data,
                )
                if ipacode.text == "__aggrsint":
                    self._assertTrue(
                        False,
                        ("The IPACode __aggrsint could be used only in the aggregated contact for test metadata."),
                        level="error",
                        **_data,
                    )
                else:
                    res = get_indicepa_by_ipacode(re.sub(r'[\s\t\n\r]*', '', ipacode.text))
                    self._assertTrue(
                        res[0] > 0,
                        "The IPACode element MUST have a valid value present on IPA",
                        test_id=["01.11.04", "01.17.14"],
                        **_data,
                    )
            else:
                self._assertFalse(
                    public,
                    "The IPACode element MUST be present",
                    test_id=["01.11.02", "01.18.03", "01.20.02"],
                    **_data,
                )

        elif public:
            if ipacode and ipacode[0].text == "__aggrsint":
                self._assertTrue(
                    False,
                    ("The IPACode __aggrsint should be used only for test metadata."),
                    level="warning",
                    **_data,
                )
        
        elif private:
            self._assertTrue(
                len(ipacode) == 0,
                "The IPACode element MUST NOT be present",
                description=ipacode,
                test_id=["01.11.01", "01.20.01"],
                **_data,
            )

        return self.is_ok(_method)

    # Per SPID è stata inglobata in test_extensions_type, usata da CIE
    def test_extensions_public_private(
        self, ext_type="Public", contact_type="other", entity_type: str = ""
    ):
        ext_type_not = "Private" if ext_type == "Public" else "Public"
        _method = f"{self.__class__.__name__}.test_extensions_public_private"
        _data = dict(references=[""], method=_method)
        # only if other, billing doesn't have any Private element in it!

        xpatt = compose_contact_type_entity_type(contact_type, entity_type)

        ctype = self.doc.xpath(
            f"//{xpatt}/Extensions/{ext_type.title()}", namespaces=XML_NAMESPACES
        )
        self._assertTrue(
            ctype,
            f"Missing ContactPerson/Extensions/{ext_type.title()}, "
            "this element MUST be present",
            test_id=["1.11.7", "1.12.5"],
            **_data,
        )
        if ctype:
            self._assertFalse(
                ctype[0].text,
                f"The {ext_type.title()} element MUST be empty",
                test_id=["1.11.8", "1.12.6"],
                **_data,
            )

        ctype = self.doc.xpath(
            f"{xpatt}/Extensions/{ext_type_not.title()}", namespaces=XML_NAMESPACES
        )
        self._assertFalse(
            ctype,
            f"The {ext_type_not.title()} element MUST not be present",
            test_id=["1.11.9", "1.12.7"],
            **_data,
        )
        return self.is_ok(_method)

    def test_Contacts_VATFC(
        self,
        contact_type: str = "other",
        entity_type: str = None,
        private=False,
        must=False,
    ):
        _method = f"{self.__class__.__name__}.test_Contacts_VATFC"
        _data = dict(references=[""], method=_method)

        xpatt = compose_contact_type_entity_type(contact_type, entity_type)

        vats = self.doc.xpath(
            f"{xpatt}/Extensions/VATNumber", namespaces=XML_NAMESPACES
        )
        if vats:
            self._assertTrue(
                (len(vats) <= 1),
                "only one VATNumber element must be present",
                description=[etree.tostring(_vats).decode() for _vats in vats],
                test_id=["01.11.05", "01.17.15 "],
                **_data,
            )
            self._assertTrue(
                vats[0].text,
                "The VATNumber element MUST have a value",
                test_id=["01.11.06", "01.17.16"],
                **_data,
            )
            if vats[0].text == "__aggrsint":
                self._assertFalse(
                    entity_type == "spid:aggregated",
                    ("The VATNumber __aggrsint should be used only for test metadata."),
                    level="warning",
                    **_data,
                )
                self._assertTrue(
                    entity_type == "spid:aggregator",
                    ("The VATNumber __aggrsint could be used only for test metadata in the aggregated contact."),
                    level="error",
                    **_data,
                )
            else:
                self._assertTrue(
                    (vats[0].text and vats[0].text[:2] in ISO3166_CODES),
                    "The VATNumber element MUST start with a valid ISO3166 Code",
                    test_id=["01.11.10", "01.17.17"],
                    **_data,
                )

        fcs = self.doc.xpath(
            f"{xpatt}/Extensions/FiscalCode", namespaces=XML_NAMESPACES
        )
        if fcs:
            self._assertTrue(
                (len(fcs) == 1),
                "only one FiscalCode element must be present",
                description=[etree.tostring(_fcs).decode() for _fcs in fcs],
                test_id=["01.11.08", "01.17.18 "],
                **_data,
            )
            fc = fcs[0]
            self._assertTrue(
                fc.text,
                "The FiscalCode element MUST have a value",
                test_id=["01.11.09", "01.17.19"],
                **_data,
            )
        if private and not len(fcs) and not len(vats):
            self._assertTrue(
                False,
                "If the VATNumber is not present, the FiscalCode element MUST be present",
                test_id=["01.11.07", "01.20.05"],
                **_data,
            )
        if must and not len(vats):
            self._assertTrue(
                False,
                "VATNumber element MUST be present",
                test_id=["01.18.04"],
                **_data,
            )
        if must and not len(fcs):
            self._assertTrue(
                False,
                "FiscalCode element MUST be present",
                test_id=["01.18.05"],
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
