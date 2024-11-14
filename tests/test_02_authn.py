import os

BASE_CMD = "python3 src/spid_sp_test/bin/spid_sp_test"
BASE_METADATA = "spid-django-other_signed.xml"
CMD = BASE_CMD + " --extra --metadata-url file://tests/metadata/{} --authn-url file://tests/authn/{} --debug ERROR"


def run_cmd(mfname, metadata = BASE_METADATA, profile="spid-sp-public", environ="") -> int:
    cmd = CMD.format(metadata, mfname)
    return os.system(f'{environ}{cmd} --profile {profile}')

def test_django_post_html():
    es = run_cmd('spid_django_post.html', environ="IDP_ENTITYID=https://localhost:8080 ")
    assert es == 0


def test_django_post():
    es = run_cmd('spid_django.xml', environ="IDP_ENTITYID=https://localhost:8080 ")
    assert es == 0


def test_django_redirect():
    """
        Must fail
        ERROR:spid_sp_test.authn_request:The ProtocolBinding attribute must be urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST - TR pag. 8  : FAILED
    """
    es = run_cmd('spid_django_redirect.url', environ="IDP_ENTITYID=https://localhost:8080 ")
    assert es != 0


def test_spid_express_no_relaystate():
    """Must fail"""
    es = run_cmd("spid_express_no_relaystate_redirect.url",
                 metadata = "spid_express_no_relaystate_metadata.xml")
    assert es != 0


def test_django_post_wrong_signature():
    es = run_cmd('spid_django_wrong_signature.xml')
    assert es != 0


def test_L2():
    """Must fail"""
    es = run_cmd("tests/authn/spid_express_forceauthn_spid_level_2.url",
                 metadata = "spid_express_forceauthn_spid_level_2_metadata.xml",
                 profile="spid-sp-private")
    assert es != 0
