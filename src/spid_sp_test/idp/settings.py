import os

from pathlib import Path
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT

# from saml2.saml import NAME_FORMAT_BASIC


BASE_DIR = Path(__file__).resolve().parent
BASE = os.environ.get("IDP_ENTITYID", "https://localhost:8443")
CERT_PATH = os.environ.get("IDP_CERT_PATH", BASE_DIR)

SAML2_IDP_CONFIG = {
    "entityid": BASE,
    "name": "SPID Test IdP",
    "service": {
        "idp": {
            "endpoints": {
                "single_sign_on_service": [
                    (f"{BASE}/samlsso", BINDING_HTTP_POST),
                    (f"{BASE}/samlsso", BINDING_HTTP_REDIRECT),
                ],
                "single_logout_service": [
                    (f"{BASE}/samlsso", BINDING_HTTP_POST),
                    (f"{BASE}/samlsso", BINDING_HTTP_REDIRECT),
                ],
            },
        },
    },
    "debug": 0,
    "key_file": f"{CERT_PATH}/private.key",
    "cert_file": f"{CERT_PATH}/public.cert",
    # "xmlsec_binary": xmlsec_path,
    "metadata": [],
    # "attribute_map_dir": full_path("attributemaps"),
    "organization": {
        "name": "Exempel AB",
        "display_name": [("Exempel AB", "se"), ("Example Co.", "en")],
        "url": "http://www.example.com/roland",
    },
    "contact_person": [
        {
            "given_name": "John",
            "sur_name": "Smith",
            "email_address": ["john.smith@example.com"],
            "contact_type": "technical",
        },
    ],
}
