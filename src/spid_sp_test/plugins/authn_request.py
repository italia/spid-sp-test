class Dummy(object):
    def __init__(self, requests_session, authn_request_url):
        self.requests_session = requests_session
        self.authn_request_url = authn_request_url

    def request(self):
        """ """
        return self.authn_request_url

    def response(self, url, data: dict = {}, **kwargs):
        """ """
        res = self.requests_session.post(url, data=data, allow_redirects=True)
        return res
