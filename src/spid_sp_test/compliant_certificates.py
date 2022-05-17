import logging

from pathlib import PosixPath
from spid_compliant_certificates.validator.validate import validate

logger = logging.getLogger(__name__)


def _get_tests(report:dict):
    _res = []
    for i in report['tests']:
        for e in i['checks']:
            _res.append(e)
    return _res


def check_certificate(cert_path:str, sector:str="public"):
    _cert = PosixPath(cert_path)
    _val = validate(_cert, sector)

    report = _val.as_dict()
    return _get_tests(report)


if __name__ == '__main__':
    cert_path = PosixPath("src/spid_sp_test/idp/public.cert")
    res = check_certificate(cert_path)
