import os

DIR='metadata'
CMD = "python3 src/spid_sp_test/bin/spid_sp_test --metadata-url file://tests/{} --extra --debug ERROR"


def run_cmd(mfname) -> int:
    cmd = CMD.format(mfname)
    print(cmd)
    return os.system(cmd)


def test_metadata_missing_eid():
    es = run_cmd(f'{DIR}/metadata_missing_entityid.xml')
    assert es != 0


def test_public_sp():
    es = run_cmd(f'{DIR}/public-sp_signed.xml')
    assert es == 0


def test_private_sp():
    es = run_cmd(f'{DIR}/private-sp_signed.xml --profile spid-sp-private')
    assert es == 0


def test_op_full():
    es = run_cmd(f'{DIR}/pub-op-full_signed.xml --profile spid-sp-op-public-full')
    assert es == 0


def test_ag_lite():
    es = run_cmd(f'{DIR}/pub-ag-lite_signed.xml --profile spid-sp-ag-public-lite')
    assert es == 0


def test_ag_full():
    es = run_cmd(f'{DIR}/pub-ag-full_signed.xml --profile spid-sp-ag-public-full')
    assert es == 0


def test_ag_lite_priv():
    es = run_cmd(f'{DIR}/pri-ag-lite_signed.xml --profile spid-sp-ag-private-lite')
    assert es == 0


def test_ag_full_priv():
    es = run_cmd(f'{DIR}/pri-ag-full_signed.xml --profile spid-sp-ag-private-full')
    assert es == 0


def test_public_cie_sp():
    es = run_cmd(f'{DIR}/public-sp-cie_signed.xml --profile cie-sp-public')
    assert es == 0


def test_public_ficep_sp():
    es = run_cmd(f'{DIR}/public-sp-eidas_signed.xml --profile ficep-eidas-sp')
    assert es == 0
