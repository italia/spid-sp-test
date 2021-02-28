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
            self.handle_result('info', f"{msg} : OK")
            return True
        else:
            self.error_counter = 0
            return False


    def handle_result(self, 
                      level:str, 
                      title:str, description:str='', 
                      traceback:str=None):
        msg = f'{title} [{description}]' if description else f'{title}'
        getattr(self.logger, level, 'debug')(msg)
        if level not in ('error', 'debug', 'critical', 'warning'):
            # here report as json
            value = f'{description}' if not traceback else f'{description}: {traceback }'
            self.results.append(
                {
                    "result": "success",
                    "test":  title,
                    "value": value
                }
            )


    def handle_error(self, error_message, description = '',
                     traceback:str=None):
        self.handle_result('error', f"{error_message} : FAILED", description)
        self.error_counter += 1
        # here report as json
        value = f'{description}' if not traceback else f'{description}: {traceback }'
        data = {
                "result": "failure",
                "test":  error_message,
                "value": value
        }
        self.errors.append(data)
        self.results.append(data)


    def _assertTrue(self, check, error_message):
        if not check:
            self.handle_error(error_message)
        else:
            self.handle_result('info', f"{error_message} : OK")


    def _assertFalse(self, check, error_message):
        if check:
            self.handle_error(error_message)
        else:
            self.handle_result('info', f"{error_message} : OK")


    def _assertIsNotNone(self, check, error_message):
        if check == True:
            self.handle_error(error_message)


    def _assertIn(self, first, second, error_message):
        if first not in second:
            self.handle_error(error_message)
        else:
            self.handle_result('info', f"{error_message} : OK")


    def _assertGreaterEqual(self, first, second, error_message):
        if not first >= second:
            self.handle_error(error_message)
        else:
            self.handle_result('info', f"{error_message} : OK")


    def _assertGreater(self, first, second, error_message):
        if not first > second:
            self.handle_error(error_message)
        else:
            self.handle_result('info', f"{error_message} : OK")


    def _assertEqual(self, first, second, error_message):
        if not first == second:
            self.handle_error(error_message)
        else:
            self.handle_result('info', f"{error_message} : OK")


    def _assertIsValidHttpsUrl(self, check, error_message):
        if not re.match('https://', check if check else ''):
            self.handle_error(error_message, description = check)
        else:
            self.handle_result('info', f"{error_message} : OK")


    def _assertIsValidHttpUrl(self, check, error_message):
        if not re.match('https?://', check if check else ''):
            self.handle_error(error_message, description = check)
        else:
            self.handle_result('info', f"{error_message} : OK")

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
