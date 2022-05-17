from tempfile import NamedTemporaryFile
from ..authn_request import get_authn_request
from ..utils import saml_from_htmlform


class Base(object):
    def __init__(
        self,
        requests_session,
        authn_request_url,
        request_method: str = "GET",
        request_body: dict = {},
        request_content_type: str = "data",
    ):
        self.requests_session = requests_session
        self.authn_request_url = authn_request_url
        self.request_method = request_method or "GET"
        self.request_body = request_body
        self.request_content_type = request_content_type

    def request(self):
        """ """
        return self.authn_request_url

    def response(self, url, data: dict = {}, **kwargs):
        """ """
        req_dict = {
            "verify": kwargs.get("verify_ssl", 0),
            "allow_redirects": kwargs.get("allow_redirects", True),
        }
        if self.request_method.upper() == "POST":
            req_dict[self.request_content_type.lower()] = self.request_body
        method = getattr(self.requests_session, self.request_method.lower())

        res = method(url, **req_dict)
        return res


class SatosaSaml2Spid(Base):
    def request(self):
        """ """
        data = get_authn_request(
            self.authn_request_url, requests_session=self.requests_session
        )
        req = data["requests_session"]
        tmp_file = NamedTemporaryFile()
        if data["method"] == "post":
            form = {
                "SAMLRequest": data["SAMLRequest"],
                "RelayState": data.get("RelayState", ""),
            }
            res = req.post(data["action"], data=form, verify=0)
            tmp_file.write(res.content)
        else:
            res = req.get(data["SAMLRequest_redirect"], verify=0)
            tmp_file.write(res.headers["Location"])

        tmp_file.seek(0)
        _data = get_authn_request(f"file://{tmp_file.name}", requests_session=req)
        return _data

    def response(self, url, data: dict = {}, **kwargs):
        """ """
        res = self.requests_session.post(
            url, data=data, verify=0, allow_redirects=False
        )

        if res.status_code != 200:
            return res

        form = saml_from_htmlform(res.content.decode())
        url = form.pop("action")
        method = getattr(self.requests_session, form.pop("method"))
        next_res = method(url, data=dict(form), verify=0)
        return next_res
