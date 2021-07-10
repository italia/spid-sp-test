from spid_sp_test.response import SpidSpResponse, SpidSpResponseCheck
from .settings import HTTP_STATUS_ERROR_CODES


def dynamic_acr(check: SpidSpResponseCheck, response_obj: SpidSpResponse, **kwargs):
    if check.get_acr() != check.response_attrs["AuthnContextClassRef"]:
        response_obj.conf["status_codes"] = HTTP_STATUS_ERROR_CODES
        try:
            level_sp = int(check.get_acr()[-1])
            level_idp = int(check.response_attrs["AuthnContextClassRef"][-1])
            if level_idp > level_sp:
                response_obj.conf["status_codes"] = [200]
        except Exception:
            pass
