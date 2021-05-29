import re

from lxml import etree
from . constants import EMAIL_REGEXP


class SpidSpMetadataCheckPrivate(object):

    def test_Contacts_Priv(self):
        entity_desc = self.doc.xpath('//ContactPerson')

        ipacode = self.doc.xpath('//ContactPerson/Extensions/IPACode')
        self._assertFalse(
            ipacode,
            'The IPACode element MUST NOT be present',
            description = ipacode,
        )

        ctype = self.doc.xpath('//ContactPerson/Extensions/Private')
        self._assertTrue(
            ctype,
            (f'Missing ContactPerson/Extensions/Private, '
             'this element MUST be present'),
            description = ctype,
        )
        if ctype:
            self._assertFalse(
                ctype[0].text,
                (f'The Private element MUST be empty'),
                description = ctype[0].text,
            )

        exts = self.doc.xpath(
            '//ContactPerson/Extensions/CessionarioCommittente'
        )
        self._assertTrue(
            (len(exts) == 1),
            ('The CessionarioCommittente element MUST be present'),
            description = exts,
        )

        if exts:
            ext = exts[0]
            company = self.doc.xpath(
                '//ContactPerson/Extensions/CessionarioCommittente/CompanyName'
            )
            if company:
                company = company[0]
                self._assertTrue(
                    company.text,
                    'If the Company element is present it MUST have a value',
                    description = company,
                )

            tise = self.doc.xpath(
                '//ContactPerson/Extensions/CessionarioCommittente/TerzoIntermediarioSoggettoEmittente'
            )
            if tise:
                tise = tise[0]
                self._assertTrue(
                    tise.text,
                    'If the TerzoIntermediarioSoggettoEmittente element if present it MUST have a value',
                    description = tise,
                )

            email = entity_desc = self.doc.xpath(
                '//ContactPerson/Extensions/CessionarioCommittente/EmailAddress'
            )
            self._assertTrue(
                email,
                'The CessionarioCommittente/EmailAddress element MUST be present',
                description = email,
            )
            if email:
                self._assertTrue(
                    email[0].text,
                    'The CessionarioCommittente/EmailAddress element MUST have a value',
                    description = email[0],
                )
                self._assertTrue(
                    re.match(EMAIL_REGEXP, email[0].text),
                    'The CessionarioCommittente/EmailAddress element MUST be a valid email address',
                    description = email[0],
                )

        ctype = self.doc.xpath('//ContactPerson/Extensions/Public')
        self._assertTrue(
            ctype,
            'The Public element MUST not be present',
            description = ctype
        )

        return self.is_ok(f'{self.__class__.__name__}.test_Contacts_Priv')
