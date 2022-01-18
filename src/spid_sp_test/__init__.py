import logging
import re

from pathlib import Path
from .constants import HTTP_NO_PORT_REGEX


BASE_DIR = Path(__file__).resolve().parent
__version__ = "1.1.3"
__name__ = "spid_sp_test"
logger = logging.getLogger(__name__)


class AbstractSpidCheck(object):
    def __init__(self, *args, **kwargs):
        self.results = []
        self.errors = []
        self.warnings = []
        self.logger = logger
        self.error_counter = 0
        self.verify_ssl = kwargs.get("verify_ssl", False)
        self.category = ""

    def report_to_dict(self):
        res = {self.category: {self.__class__.__name__: self.results}}
        return res

    def is_ok(self, msg):
        if not self.error_counter:
            # self.handle_result(
            # "info",
            # msg,
            # method = method or msg
            # )
            return True
        else:
            self.error_counter = 0
            return False

    def handle_result(
        self,
        level: str,
        title: str,
        description: str = "",
        traceback: str = None,
        references: list = [],
        method: str = "",
        test_id: str = "",
    ):
        msg = f"{title}"
        getattr(self.logger, level, "debug")(f"{method}: {msg}")
        value = f"{description}" if not traceback else f"{description}: {traceback }"

        data = {
            "test_id": test_id,
            "test": title,
            "value": value.decode() if isinstance(value, bytes) else value,
            "references": references,
            "method": method,
        }

        if level not in ("error", "debug", "critical", "warning"):
            # here report as json
            data["result"] = "success"
            self.results.append(data)
        elif level in ("error", "critical"):
            self.handle_error(title, description, traceback)
        elif level == "warning":
            data["result"] = "warning"
            self.results.append(data)
            self.warnings.append(data)

    def handle_error(
        self,
        error_message,
        description="",
        traceback: str = None,
        references: list = [],
        method: str = "",
        test_id: str = "",
    ):
        self.logger.error(error_message)
        self.error_counter += 1
        # here report as json
        value = f"{description}" if not traceback else f"{description}: {traceback }"
        data = {
            "test_id": test_id,
            "result": "failure",
            "test": error_message,
            "value": value.decode() if isinstance(value, bytes) else value,
            "references": references,
            "method": method,
        }
        self.errors.append(data)
        self.results.append(data)

    def _assert(
        self,
        check: bool,
        error_message: str,
        description="",
        traceback: str = None,
        level: str = "info",
        **kwargs,
    ):
        if level == "warning":
            # overwrite to info is warning doens't happen.
            if check:
                level = "info"
        elif not check:
            level = "error"
        self.handle_result(level, error_message, description, traceback, **kwargs)

    def _assertTrue(self, *args, **kwargs):
        self._assert(*args, **kwargs)

    def _assertFalse(self, check, *args, **kwargs):
        self._assert(not check, *args, **kwargs)

    def _assertIsValidHttpsUrl(self, check, *args, **kwargs):
        self._assert(re.match("https://", check if check else ""), *args, **kwargs)

    def _assertHttpUrlWithoutPort(self, check, *args, **kwargs):
        self._assert(
            re.match(HTTP_NO_PORT_REGEX, check if check else ""), *args, **kwargs
        )

    def _assertIsValidHttpUrl(self, check, *args, **kwargs):
        self._assert(re.match("https?://", check if check else ""), *args, **kwargs)

    def handle_init_errors(self, method, description, traceback=""):
        self._assertTrue(
            False,
            method,
            description=description,
            traceback=traceback,
            method=method,
            test_id=[],
        )
        self.is_ok(method)
        raise Exception(traceback)

    # maybe useful .. one day ?!
    # idp_server = self.idp()
    # pysaml2 auth req object with signature check

    # SPID IdP not completely compliant to SAML2-core about Destination attribute
    # saml2.request:http://localhost:8088 not in ['http://localhost:54321/sso']
    # try:
    # req_obj = idp_server.parse_authn_request(self.authn_request_encoded,
    # BINDING_HTTP_POST)
    # except OtherError as e:
    # pass
