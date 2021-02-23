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
        

    def report_to_json(self):
        pass


    def is_ok(self, msg):
        if not self.error_counter:
            self.handle_result('info', msg)
            return True
        else:
            self.error_counter = 0
            return False

    
    def handle_result(self, 
                      level:str, 
                      title:str, description:str='', 
                      traceback:str=None):
        msg = f'{title} [{description}]' if description else f'{title}'
        getattr(self.logger, level, 'warning')(msg)
        if level not in ('error', 'debug', 'critical', 'warning'):
            # here report as json
            self.results.append(
                {
                    "result": "success",
                    "test":  title,
                    "value": description
                }
            )
    
    def handle_error(self, error_message, description = ''):
        self.handle_result('error', error_message, description)
        self.error_counter += 1
        # here report as json
        data = {
                "result": "failure",
                "test":  error_message,
                "value": description
        }
        self.errors.append(data)
        self.results.append(data)


    def _assertTrue(self, check, error_message):
        if not check:
            self.handle_error(error_message)


    def _assertFalse(self, check, error_message):
        if check:
            self.handle_error(error_message)


    def _assertIsNotNone(self, check, error_message):
        if check == True:
            self.handle_error(error_message)


    def _assertIn(self, first, second, error_message):
        if first not in second:
            self.handle_error(error_message)


    def _assertGreaterEqual(self, first, second, error_message):
        if not first >= second:
            self.handle_error(error_message)


    def _assertGreater(self, first, second, error_message):
        if not first > second:
            self.handle_error(error_message)


    def _assertEqual(self, first, second, error_message):
        if not first == second:
            self.handle_error(error_message)


    def _assertIsValidHttpsUrl(self, check, error_message):
        if check[0:8] != 'https://':
            self.handle_error(error_message, description = check)


    def _assertIsValidHttpUrl(self, check, error_message):
        if not re.match('https?://', check):
            self.handle_error(error_message, description = check)



        # idp_server = self.idp()
        # pysaml2 auth req object with signature check
        
        # SPID IdP not completely compliant to SAML2-core about Destination attribute
        # saml2.request:http://localhost:8088 not in ['http://localhost:54321/sso']
        # try:
            # req_obj = idp_server.parse_authn_request(self.authn_request_encoded, 
                                                     # BINDING_HTTP_POST)
        # except OtherError as e:
            # pass
