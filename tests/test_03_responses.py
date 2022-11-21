import os

CMD = "python3 src/spid_sp_test/bin/spid_sp_test --metadata-url file://tests/metadata/spid-django-other_signed.xml --authn-url file://tests/authn/spid_django_post.html --extra --debug ERROR -tr -nsr"


def test_all_default_responses():
    es = os.system(CMD)
    assert es == 0
