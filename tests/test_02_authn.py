import os

CMD = "python3 src/spid_sp_test/spid_sp_test --metadata-url file://tests/metadata/spid-django-other.xml --authn-url file://tests/authn/{}"


def run_cmd(mfname) -> int:
    cmd = CMD.format(mfname)
    return os.system(cmd)


def test_django_post():
    es = run_cmd(f'spid_django_post.html')
    assert es == 0


def test_django_redirect():
    """
        ERROR:spid_sp_test.authn_request:The ProtocolBinding attribute must be urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST - TR pag. 8  : FAILED
    """
    es = run_cmd(f'spid_django_redirect.url')
    assert es != 0
