from lxml import etree
from . authn_request import SpidSpAuthnReqCheck


class SpidSpAuthnReqCheckExtra(SpidSpAuthnReqCheck):

    def __init__(self, *args, **kwargs):

        super(SpidSpAuthnReqCheckExtra, self).__init__(*args, **kwargs)
        self.category = 'authnrequest_strict'

    def test_AuthnRequest_extra(self):
        '''Test the compliance of AuthnRequest element'''

        # ForceAuthn must be true if 'Comparison' is 'minimum' and
        # SPID level is L1


        req = self.doc.xpath('/AuthnRequest')
        rac = None
        acr = None
        if req:
            rac = req[0].xpath('./RequestedAuthnContext')
        if rac:
            acr = rac[0].xpath('./AuthnContextClassRef')

        if req and rac and acr:
            req = req[0]
            rac = rac[0]
            acr = acr[0]

            if (rac.get('Comparison') == 'minimum'
                    and acr.text == 'https://www.spid.gov.it/SpidL1'):
                self._assertTrue(
                    ('ForceAuthn' in req.attrib),
                    'The ForceAuthn attribute must be present '
                    'because of minimum/SpidL1',
                    description = req.attrib
                )
                self._assertEqual(
                    req.get('ForceAuthn').lower(),
                    'true',
                    'The ForceAuthn attribute must be True '
                    'because of minimum/SpidL1',
                    description = req.attrib
                )
        else:
            self.handle_error('AuthnRequest or RequestAuthnContext or AytnContextClassRef missing',)

        return self.is_ok(f'{self.__class__.__name__}.test_AuthnRequest_extra')

    def test_all(self):
        self.test_AuthnRequest_extra()
