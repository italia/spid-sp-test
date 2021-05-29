import re

from lxml import etree


class SpidSpMetadataCheckPrivate(object):

    def test_Contacts_Priv(self):
        entity_desc = self.doc.xpath('//ContactPerson')
        desc = [etree.tostring(ent).decode() for ent in entity_desc if entity_desc]
        error_kwargs = dict(description = desc) if desc else {}

        if self.production:
            ipacode = self.doc.xpath('//ContactPerson/Extensions/IPACode')
            if ipacode:
                _msg = 'The IPACode element MUST NOT be present'
                self.handle_error(_msg, **error_kwargs)

        ctype = self.doc.xpath('//ContactPerson/Extensions/Private')
        if not ctype:
            _msg = (f'Missing ContactPerson/Extensions/Private, '
                    'this element MUST be present')
            self.handle_error(_msg, **error_kwargs)
        elif ctype[0].text:
            _msg = (f'The Private element MUST be empty')
            self.handle_error(_msg, **error_kwargs)

        exts = self.doc.xpath('//ContactPerson/Extensions/CessionarioCommittente')
        if len(exts) != 1:
            _msg = 'The CessionarioCommittente element MUST be present'
            self.handle_error(_msg, **error_kwargs)
        if exts:
            ext = exts[0]

            company = self.doc.xpath(
                '//ContactPerson/Extensions/CessionarioCommittente/CompanyName'
            )
            if company:
                company = company[0]
                if not company.text:
                    _msg = 'If the Company element if present it MUST have a value'
                    self.handle_error(_msg, **error_kwargs)

            tise = self.doc.xpath(
                '//ContactPerson/Extensions/CessionarioCommittente/TerzoIntermediarioSoggettoEmittente'
            )
            if tise:
                tise = tise[0]
                if not tise.text:
                    _msg = 'If the TerzoIntermediarioSoggettoEmittente element if present it MUST have a value'
                    self.handle_error(_msg, **error_kwargs)

            email = entity_desc = self.doc.xpath(
                '//ContactPerson/Extensions/CessionarioCommittente/EmailAddress'
            )
            email_regex = '^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$'
            if not email:
                _msg = 'The CessionarioCommittente/EmailAddress element MUST be present'
                self.handle_error(_msg, **error_kwargs)
            elif not email[0].text:
                _msg = 'The CessionarioCommittente/EmailAddress element MUST have a value'
                self.handle_error(_msg, **error_kwargs)
            elif not re.match(email_regex, email[0].text):
                _msg = 'The CessionarioCommittente/EmailAddress element MUST be a valid email address'
                self.handle_error(_msg, **error_kwargs)

        ctype = self.doc.xpath('//ContactPerson/Extensions/Public')
        if ctype:
            _msg = ('The Public element MUST not be present')
            self.handle_error(_msg, **error_kwargs)

        return self.is_ok(f'{self.__class__.__name__}.test_Contacts_Priv')
