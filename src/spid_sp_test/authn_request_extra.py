import re

from .authn_request import SpidSpAuthnReqCheck


class SpidSpAuthnReqCheckExtra(SpidSpAuthnReqCheck):
    def __init__(self, *args, **kwargs):

        super(SpidSpAuthnReqCheckExtra, self).__init__(*args, **kwargs)
        self.category = "authnrequest_extra"

    def test_AuthnRequest_SPID_extra(self):
        """Test the compliance of AuthnRequest element"""

        # ForceAuthn MUST be true if 'Comparison' is 'minimum' and
        # SPID level is L1
        _method = f"{self.__class__.__name__}.test_AuthnRequest_SPID_extra"
        _data = dict(
            test_id="",
            references=[],
            method=_method,
        )

        req = self.doc.xpath("/AuthnRequest")
        rac = None
        acr = None
        if req:
            rac = req[0].xpath("./RequestedAuthnContext")
        if rac:
            acr = rac[0].xpath("./AuthnContextClassRef")

        if req and rac and acr:
            req = req[0]
            rac = rac[0]
            acr = acr[0]

            if rac.get("Comparison") in ("minimum", "exact") and acr.text in (
                "https://www.spid.gov.it/SpidL2",
                "https://www.spid.gov.it/SpidL3",
            ):
                self._assertTrue(
                    ("ForceAuthn" in req.attrib),
                    "The ForceAuthn attribute MUST be present "
                    "because of minimum/SpidL2",
                    description=req.attrib,
                    **_data,
                )
                self._assertTrue(
                    req.get("ForceAuthn", "").lower() in ("true", 1, "1"),
                    "The ForceAuthn attribute MUST be True "
                    "because of minimum/SpidL2",
                    description=req.attrib,
                    **_data,
                )
        else:
            self.handle_error(
                "AuthnRequest or RequestAuthnContext or AuthnContextClassRef missing",
                **_data,
            )

        return self.is_ok(_method)

    def test_authnrequest_no_newlines(self):
        _method = f"{self.__class__.__name__}.test_authnrequest_no_newlines"
        self._assertFalse(
            re.match(r"^[\t\n\s\r\ ]*", self.authn_request_decoded),
            (
                "The XML of authn request should not "
                "contains newlines at the beginning."
            ),
            description=self.metadata[0:10],
            level="warning",
            method=_method,
        )
        return self.is_ok(_method)

    def test_profile_spid_sp(self):
        super().test_profile_spid_sp()
        self.test_AuthnRequest_SPID_extra()
