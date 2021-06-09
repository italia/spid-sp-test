import logging
import re

from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
logger = logging.getLogger(__name__)


class AbstractSpidCheck(object):
    def __init__(self, *args, **kwargs):
        self.results = []
        self.errors = []
        self.logger = logger
        self.error_counter = 0
        self.verify_ssl = kwargs.get('verify_ssl', False)
        self.category = ''

    def report_to_dict(self):
        res = {
            self.category: {
                self.__class__.__name__: self.results
            }
        }

        return res

    def is_ok(self, msg):
        if not self.error_counter:
            self.handle_result('info', f"{msg}")
            return True
        else:
            self.error_counter = 0
            return False

    def handle_result(self,
                      level: str,
                      title: str, description: str = '',
                      traceback: str = None):
        msg = f'{title}'
        getattr(self.logger, level, 'debug')(msg)
        value = f'{description}' if not traceback else f'{description}: {traceback }'
        if level not in ('error', 'debug', 'critical', 'warning'):
            # here report as json
            self.results.append(
                {
                    "result": "success",
                    "test": title,
                    # "value": value
                }
            )
        elif level in ('error', 'critical'):
            self.handle_error(title,
                              description,
                              traceback)
        elif level == 'warning':
            self.results.append(
                {
                    "result": "warning",
                    "test": title,
                    "value": value,
                }
            )

    def handle_error(self, error_message, description='',
                     traceback: str = None):
        getattr(self.logger, 'error')(error_message)
        self.error_counter += 1
        # here report as json
        value = f'{description}' if not traceback else f'{description}: {traceback }'
        data = {
            "result": "failure",
            "test": error_message,
            "value": value
        }
        self.errors.append(data)
        self.results.append(data)

    def _assert(self, check:bool, error_message:str,
                description='', traceback: str = None,
                level: str = 'info'):
        if not check and level == 'info':
            self.handle_error(error_message, description, traceback)
        elif not check and level == 'warning':
            self.handle_result(level, f"{error_message}", description, traceback)
        else:
            level = 'info' if level in ('warning',) else level
            self.handle_result(level, f"{error_message}", description, traceback)

    def _assertTrue(self, check, error_message,
                    description='', traceback: str = None,
                    level: str = 'info'):
        self._assert(check, error_message, description, traceback, level)

    def _assertFalse(self, check, error_message,
                     description='', traceback: str = None,
                     level: str = 'info'):
        self._assert(not check, error_message, description, traceback, level)

    def _assertIsNotNone(self, check, error_message,
                         description='', traceback: str = None,
                         level: str = 'info'):
        self._assert(check, error_message, description, traceback, level)

    def _assertIn(self, first, second, error_message,
                  description='', traceback: str = None,
                  level: str = 'info'):
        self._assert((first in second),
                     error_message, description, traceback, level)

    def _assertGreaterEqual(self, first, second, error_message,
                            description='', traceback: str = None,
                            level: str = 'info'):
        self._assert((first >=second),
                     error_message, description, traceback, level)

    def _assertGreater(self, first, second, error_message,
                       description='', traceback: str = None,
                       level: str = 'info'):
        self._assert((first > second),
                     error_message, description, traceback, level)

    def _assertEqual(self, first, second, error_message,
                     description='', traceback: str = None,
                     level: str = 'info'):
        self._assert((first == second),
                     error_message, description, traceback, level)

    def _assertIsValidHttpsUrl(self, check, error_message,
                               description='', traceback: str = None,
                               level: str = 'info'):
        self._assert(re.match('https://', check if check else ''),
                     description, traceback, level)

    def _assertIsValidHttpUrl(self, check, error_message,
                              description='', traceback: str = None,
                              level: str = 'info'):
        self._assert(re.match('https?://', check if check else ''),
                     description, traceback, level)

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
