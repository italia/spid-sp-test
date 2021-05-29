import re

from lxml import etree
from . indicepa import get_indicepa_by_ipacode


class SpidSpMetadataCheckPublic(object):

    def test_Contacts_PubPriv(self):
        entity_desc = self.doc.xpath('//ContactPerson')
        desc = [etree.tostring(ent).decode() for ent in entity_desc if entity_desc]
        error_kwargs = dict(description = desc) if desc else {}

        if not entity_desc[0].attrib.get('contactType'):
            _msg = (f'Missing contactType in {self.doc.attrib}: '
                    'The contactType attribute MUST be present - TR pag. 19')
            self.handle_error(_msg, **error_kwargs)
        # elif len(entity_desc) > 1:
            # _msg = 'Only one contactType element MUST be present - TR pag. 19'
            # self.handle_error(_msg, **error_kwargs)
        elif not entity_desc[0].get('contactType'):
            _msg = 'The contactType attribute MUST have a value - TR pag. 19'
            self.handle_error(_msg, **error_kwargs)
        elif entity_desc[0].get('contactType') != 'other':
            _msg = 'The contactType attribute MUST have a value - TR pag. 19'
            self.handle_error(_msg, **error_kwargs)

        others = self.doc.xpath('//ContactPerson[@contactType="other"]')
        if len(others) != 1:
            _msg = 'Only one ContactPerson element of contactType "other" MUST be present'
            self.handle_error(_msg, **error_kwargs)

        exts = self.doc.xpath('//ContactPerson/Extensions')
        if len(others) != 1:
            _msg = 'Only one Extensions element inside ContactPerson element MUST be present'
            self.handle_error(_msg, **error_kwargs)

        orgs = self.doc.xpath('//EntityDescriptor/Organization/OrganizationName')
        if orgs:
            org = orgs[1]
            company = self.doc.xpath('//ContactPerson/Extensions/CompanyName')
            if company:
                company = company[0]
                if company.text != org.text:
                    _msg = 'If the Company element is present it MUST be equal to OrganizationName'
                    self.handle_error(_msg, **error_kwargs)


        email = entity_desc = self.doc.xpath('//ContactPerson/EmailAddress')
        email_regex = '^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,3}$'
        if not email:
            _msg = 'The EmailAddress element MUST be present'
            self.handle_error(_msg, **error_kwargs)
        elif not email[0].text:
            _msg = 'The EmailAddress element MUST have a value'
            self.handle_error(_msg, **error_kwargs)
        elif not re.match(email_regex, email[0].text):
            _msg = 'The EmailAddress element MUST be a valid email address'
            self.handle_error(_msg, **error_kwargs)

        phone = entity_desc = self.doc.xpath('//ContactPerson/TelephoneNumber')
        if phone:
            phone = phone[0].text
            if not phone:
                _msg = 'The TelephoneNumber element MUST have a value'
                self.handle_error(_msg, **error_kwargs)
            elif ' ' in phone:
                _msg = 'The TelephoneNumber element MUST not contain spaces'
                self.handle_error(_msg, **error_kwargs)
            elif phone[0:3] != '+39':
                _msg = 'The TelephoneNumber element MUST start with “+39”'
                self.handle_error(_msg, **error_kwargs)

        return self.is_ok(f'{self.__class__.__name__}.test_Contacts_PubPriv')

    def test_Contacts_Pub(self):
        entity_desc = self.doc.xpath('//ContactPerson')
        desc = [etree.tostring(ent).decode() for ent in entity_desc if entity_desc]
        error_kwargs = dict(description = desc) if desc else {}

        if self.production:
            ipacode = self.doc.xpath('//ContactPerson/Extensions/IPACode')
            if not ipacode:
                _msg = 'The IPACode element MUST be present'
                self.handle_error(_msg, **error_kwargs)
            elif ipacode:
                ipacode = ipacode[0]
                if not ipacode.text:
                    _msg = 'The IPACode element MUST have a value'
                    self.handle_error(_msg, **error_kwargs)
                elif get_indicepa_by_ipacode(ipacode.text)[0] != 1:
                    _msg = 'The IPACode element MUST have a valid value present on IPA '
                    self.handle_error(_msg, **error_kwargs)

        ctype = self.doc.xpath('//ContactPerson/Extensions/Public')
        if not ctype:
            _msg = (f'Missing ContactPerson/Extensions/Public, '
                    'this element MUST be present')
            self.handle_error(_msg, **error_kwargs)
        elif ctype[0].text:
            _msg = (f'The Public element MUST be empty')
            self.handle_error(_msg, **error_kwargs)

        ctype = self.doc.xpath('//ContactPerson/Extensions/Private')
        if ctype:
            _msg = ('The Private element MUST not be present')
            self.handle_error(_msg, **error_kwargs)

        return self.is_ok(f'{self.__class__.__name__}.test_Contacts_Pub')

    def test_Contacts_VATFC(self):
        entity_desc = self.doc.xpath('//ContactPerson')
        desc = [etree.tostring(ent).decode() for ent in entity_desc if entity_desc]
        error_kwargs = dict(description = desc) if desc else {}

        vat = self.doc.xpath('//ContactPerson/Extensions/VATNumber')
        if vat:
            if len(vat) != 1:
                _msg = 'only one VATNumber element must be present'
                self.handle_error(_msg, **error_kwargs)
            vat = vat[0]
            if not vat.text:
                _msg = 'The VATNumber element MUST have a value'
                self.handle_error(_msg, **error_kwargs)


        fc = self.doc.xpath('//ContactPerson/Extensions/FiscalCode')
        if fc:
            if len(fc) != 1:
                _msg = 'only one FiscalCode element must be present'
                self.handle_error(_msg, **error_kwargs)
            fc = fc[0]
            if not fc.text:
                _msg = 'The FiscalCode element MUST have a value'
                self.handle_error(_msg, **error_kwargs)

        return self.is_ok(f'{self.__class__.__name__}.test_Contacts_VATFC')
