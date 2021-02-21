import logging
import re

from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
logger = logging.getLogger(__name__)


class AbstractSpidCheck(object):
    def __init__(self, *args, **kwargs):
        self.messages = []
        self.errors = []
        self.logger = logger
        self.error_counter = 0


    def report_to_json(self):
        pass


    def is_ok(self, msg):
        if not self.error_counter:
            self.handle_result('info', msg)
            return True

    
    def handle_result(self, 
                      level:str, 
                      title:str, description:str='', traceback:str=None):
        msg = f'{title} [{description}]' if description else f'{title}'
        getattr(self.logger, level, 'warning')(msg)

    
    def handle_error(self, error_message, description = ''):
        self.handle_result('error', error_message, description)
        self.error_counter += 1

    
    def _assertTrue(self, check, error_message):
        if not check:
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
