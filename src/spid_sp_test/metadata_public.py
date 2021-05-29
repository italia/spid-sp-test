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

        exts = self.doc.xpath('//ContactPerson/Extensions')
        self._assertTrue(
            len(exts) == 1,
            'Only one Extensions element inside ContactPerson element MUST be present',
            description = exts
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


        email = entity_desc = self.doc.xpath('//ContactPerson/EmailAddress')
        self._assertTrue(
            email,
            'The EmailAddress element MUST be present',
            description = email,
        )
        if email:
            self._assertTrue(
                email[0].text,
                'The EmailAddress element MUST have a value',
                description = email[0],
            )
            self._assertTrue(
                re.match(EMAIL_REGEXP, email[0].text),
                'The EmailAddress element MUST be a valid email address',
                description = email[0],
            )

        phone = entity_desc = self.doc.xpath('//ContactPerson/TelephoneNumber')
        if phone:
            phone = phone[0].text
            self._assertTrue(
                phone,
                'The TelephoneNumber element MUST have a value',
            )
            self._assertTrue(
                (' ' not in phone),
                'The TelephoneNumber element MUST not contain spaces',
                description = phone,
            )
            self._assertTrue(
                (phone[0:3] == '+39'),
                'The TelephoneNumber element MUST start with "+39"',
                description = phone,
            )

        return self.is_ok(f'{self.__class__.__name__}.test_Contacts_PubPriv')

    def test_Contacts_Pub(self):
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

        ctype = self.doc.xpath('//ContactPerson/Extensions/Public')
        self._assertTrue(
            ctype,
            'Missing ContactPerson/Extensions/Public, this element MUST be present',
        )
        if ctype:
            self._assertFalse(
                ctype[0].text,
                'The Public element MUST be empty',
            )

        ctype = self.doc.xpath('//ContactPerson/Extensions/Private')
        self._assertFalse(
            ctype,
            'The Private element MUST not be present',
        )

        return self.is_ok(f'{self.__class__.__name__}.test_Contacts_Pub')

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
