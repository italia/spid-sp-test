import os

DIR='metadata'
CMD = "python3 src/spid_sp_test/spid_sp_test --metadata-url file://tests/{} -l xsd_check"


def run_cmd(mfname) -> int:
    cmd = CMD.format(mfname)
    return os.system(cmd)


def test_metadata_missing_eid():
    es = run_cmd(f'{DIR}/metadata_missing_entityid.xml')
    assert es != 0


def test_public_sp():
    es = run_cmd(f'{DIR}/public-sp.xml')
    assert es == 0


def test_private_sp():
    es = run_cmd(f'{DIR}/private-sp.xml')
    assert es == 0


def test_op_full():
    es = run_cmd(f'{DIR}/pub-op-full.xml')
    assert es == 0


def test_satosa_billing():
    es = run_cmd(f'{DIR}/satosa-saml2spid-billing-xml')
    assert es == 0


def test_satosa_other():
    es = run_cmd(f'{DIR}/satosa-saml2spid-other-xml')
    assert es == 0


def test_django_billing():
    es = run_cmd(f'{DIR}/spid-django-billing.xml')
    assert es == 0


def test_django_other():
    es = run_cmd(f'{DIR}/spid-django-other.xml')
    assert es == 0


# TODO - still fails
# def test_pub_ag_full():
    # """
        # Reason: The content of element 'md:ContactPerson' is not complete. Tag md:EmailAddress expected.
    # """
    # es = run_cmd('pub-ag-full.xml')
    # assert es == 0


# def test_pub_ag_light():
    # """
        # Reason: The content of element 'md:ContactPerson' is not complete. Tag md:EmailAddress expected.
    # """
    # es = run_cmd('pub-ag-lite.xml')
    # assert es == 0
