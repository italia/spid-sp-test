import re

from lxml import etree

from . constants import EMAIL_REGEXP
from . indicepa import get_indicepa_by_ipacode


class SpidSpMetadataCheckPublic(object):

    def test_Contacts_PubPriv(self, contact_type="other"):
        entity_desc = self.doc.xpath('//ContactPerson')

        self._assertTrue(entity_desc, 'ContactPerson MUST be present')

        if entity_desc:
            self._assertTrue(
                entity_desc[0].attrib.get('contactType'),
                (f'Missing contactType in {entity_desc[0].attrib}: '
                 'The contactType attribute MUST be present - TR pag. 19')
            )
            self._assertTrue(
                entity_desc[0].get('contactType'),
                'The contactType attribute MUST have a value - TR pag. 19'
            )
            self._assertTrue(
                entity_desc[0].get('contactType') == 'other',
                'The contactType must be "other" - TR pag. 19',
                description = entity_desc[0].get('contactType')
            )

        others = self.doc.xpath(
            f'//ContactPerson[@contactType="{contact_type}"]')
        self._assertTrue(
            len(others) == 1,
            f'Only one ContactPerson element of contactType "{contact_type}" MUST be present',
            description = others
        )

        return self.is_ok(f'{self.__class__.__name__}.test_Contacts_PubPriv')

    def test_Extensions_PubPriv(self):
        _conts = self.doc.xpath('//ContactPerson')

        for cont in _conts:
            ext_cnt = 0
            for child in cont.getchildren():
                if child.tag == 'Extension':
                    ext_cnt += 1

            self._assertFalse(
                ext_cnt > 1,
                'Only one Extensions element inside ContactPerson element MUST be present',
                description = etree.tostring(cont).decode()
            )

        orgs = self.doc.xpath('//EntityDescriptor/Organization/OrganizationName')
        if len(orgs) >= 1:
            org = orgs[0]
            company = self.doc.xpath('//ContactPerson/Extensions/CompanyName')
            if company:
                company = company[0]
                self._assertTrue(
                    company.text == org.text,
                    'If the Company element if present it MUST be equal to OrganizationName',
                    description = (company.text, org.text)
                )

        return self.is_ok(f'{self.__class__.__name__}.test_Extensions_PubPriv')

    def test_contactperson_email(self,
                                 email_xpath='//ContactPerson/EmailAddress'):
        email = entity_desc = self.doc.xpath(email_xpath)
        self._assertTrue(
            email,
            f'The {email_xpath} element MUST be present',
            description = email,
        )
        if email:
            self._assertTrue(
                email[0].text,
                f'The {email_xpath} element MUST have a value',
                description = email[0],
            )
            self._assertTrue(
                re.match(EMAIL_REGEXP, email[0].text),
                f'The {email_xpath} element MUST be a valid email address',
                description = email[0],
            )
        return self.is_ok(f'{self.__class__.__name__}.test_contactperson_email-{email_xpath}')

    def test_contactperson_phone(self, phone_xpath='//ContactPerson/TelephoneNumber'):
        phone = entity_desc = self.doc.xpath(phone_xpath)
        if phone:
            phone = phone[0].text
            self._assertTrue(
                phone,
                f'The {phone_xpath} element MUST have a value',
            )
            self._assertTrue(
                (' ' not in phone),
                f'The {phone_xpath} element MUST not contain spaces',
                description = phone,
            )
            self._assertTrue(
                (phone[0:3] == '+39'),
                f'The {phone_xpath} element MUST start with "+39"',
                description = phone,
            )

        return self.is_ok(f'{self.__class__.__name__}.test_contactperson_phone')


    def test_Contacts_IPACode(self):
        entity_desc = self.doc.xpath('//ContactPerson')

        if self.production:
            ipacode = self.doc.xpath('//ContactPerson/Extensions/IPACode')
            self._assertTrue(
                ipacode,
                'The IPACode element MUST be present',
            )
            if ipacode:
                ipacode = ipacode[0]
                self._assertTrue(
                    ipacode.text,
                    'The IPACode element MUST have a value',
                )
                self._assertTrue(
                    ipacode.text,
                    'The IPACode element MUST have a value',
                )
                self._assertTrue(
                    get_indicepa_by_ipacode(ipacode.text)[0] == 1,
                    'The IPACode element MUST have a valid value present on IPA',
                )

        return self.is_ok(f'{self.__class__.__name__}.test_Contacts_IPACode')

    def test_extensions_public_private(self, ext_type="Public"):
        ext_type_not = "Private" if ext_type == "Public" else "Public"

        ctype = self.doc.xpath(f'//ContactPerson/Extensions/{ext_type.title()}')
        self._assertTrue(
            ctype,
            f'Missing ContactPerson/Extensions/{ext_type.title()}, this element MUST be present',
        )
        if ctype:
            self._assertFalse(
                ctype[0].text,
                f'The {ext_type.title()} element MUST be empty',
            )

        ctype = self.doc.xpath(f'//ContactPerson/Extensions/{ext_type_not.title()}')
        self._assertFalse(
            ctype,
            f'The {ext_type_not.title()} element MUST not be present',
        )
        return self.is_ok(f'{self.__class__.__name__}.test_extentions_public')

    def test_Contacts_VATFC(self):
        entity_desc = self.doc.xpath('//ContactPerson')

        vat = self.doc.xpath('//ContactPerson/Extensions/VATNumber')
        self._assertTrue(
            (len(vat) == 1),
            'only one VATNumber element must be present',
            description = vat
        )
        if vat:
            vat = vat[0]
            self._assertTrue(
                vat.text,
                'The VATNumber element MUST have a value',
            )

        fc = self.doc.xpath('//ContactPerson/Extensions/FiscalCode')
        if fc:
            self._assertTrue(
                (len(fc) == 1),
                'only one FiscalCode element must be present',
                description = fc
            )
            fc = fc[0]
            self._assertTrue(
                fc.text,
                'The FiscalCode element MUST have a value',
            )

        return self.is_ok(f'{self.__class__.__name__}.test_Contacts_VATFC')
