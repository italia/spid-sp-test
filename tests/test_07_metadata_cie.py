import pytest

from . import get_md_check

md_kwargs = {
    'xsds_files_path': "src/spid_sp_test/xsd/cie/"
}


def test_cie_metadata_0_signed():
    metadata_url = 'file://tests/metadata/cie/0-signed.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_0_Federazione_convalida_OK():
    metadata_url = 'file://tests/metadata/cie/0.Federazione_convalida_OK.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_0():
    metadata_url = 'file://tests/metadata/cie/0.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_1():
    metadata_url = 'file://tests/metadata/cie/1.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_2_1():
    metadata_url = 'file://tests/metadata/cie/2.1.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_2_2a():
    metadata_url = 'file://tests/metadata/cie/2.2a.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_EntityDescriptor()
    assert not md.errors


def test_cie_metadata_2_2b():
    metadata_url = 'file://tests/metadata/cie/2.2b.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_profile_cie_sp_public()
    assert md.errors


def test_cie_metadata_2_2b2():
    metadata_url = 'file://tests/metadata/cie/2.2b2.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_2():
    metadata_url = 'file://tests/metadata/cie/2.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


# TODO - qui fallisce la verifica della firma
def test_cie_metadata_3_1_signed():
    # """
    # Verificare che il certificato X509  non contenga le seguenti informazioni:
        # • name (OID 2.5.4.41),
        # • surname (OID 2.5.4.42),
        # • initials (OID 2.5.4.43),
        # • generationQualifier (OID 2.5.4.44),
        # • familyInformation (OID 2.5.4.64),
        # • pseudonym (OID 2.5.4.65).
    # """
    # logger.warning("test_cie_metadata_3_1_signed not implemented yet")
    metadata_url = 'file://tests/metadata/cie/3.1-signed.xml'
    md = get_md_check(metadata_url)
    md.test_xmldsig()
    assert md.errors


# TODO - verificare che il certificato sia valido
def test_cie_metadata_3_2():
    metadata_url = 'file://tests/metadata/cie/3.2.xml'
    md = get_md_check(metadata_url)
    md.test_Signature()
    assert md.errors


def test_cie_metadata_3_3_sha1():
    metadata_url = 'file://tests/metadata/cie/3.3-sha1.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_Signature()
    assert md.errors


def test_cie_metadata_3_3():
    metadata_url = 'file://tests/metadata/cie/3.3.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_Signature()
    assert md.errors


def test_cie_metadata_3_4_rsa_512():
    metadata_url = 'file://tests/metadata/cie/3.4-rsa_512.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_Signature()
    assert md.errors


# TODO - lunghezza certificato minima
def test_cie_metadata_3_4():
    metadata_url = 'file://tests/metadata/cie/3.4.xml'
    md = get_md_check(metadata_url)
    md.test_Signature()
    assert not md.errors


# qui la firma fallisce, deve fallire
def test_cie_metadata_3_5():
    metadata_url = 'file://tests/metadata/cie/3.5.xml'
    md = get_md_check(metadata_url)
    md.test_xmldsig()
    assert md.errors


def test_cie_metadata_3():
    metadata_url = 'file://tests/metadata/cie/3.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_1():
    metadata_url = 'file://tests/metadata/cie/4.1.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_10():
    metadata_url = 'file://tests/metadata/cie/4.10.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_11():
    metadata_url = 'file://tests/metadata/cie/4.11.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_SingleLogoutService()
    assert md.errors


def test_cie_metadata_4_12():
    metadata_url = 'file://tests/metadata/cie/4.12.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_13():
    metadata_url = 'file://tests/metadata/cie/4.13.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_14():
    metadata_url = 'file://tests/metadata/cie/4.14.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    # L'elemento <AssertionConsumingService> obbligatorio
    assert md.errors


def test_cie_metadata_4_15():
    metadata_url = 'file://tests/metadata/cie/4.15.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_16():
    metadata_url = 'file://tests/metadata/cie/4.16.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_AssertionConsumerService()
    # L'attributo location presente in ogni istanza dell'elemento <AssertionConsumerService> deve contenere un URL HTTPS valido
    assert md.errors


def test_cie_metadata_4_17a():
    metadata_url = 'file://tests/metadata/cie/4.17a.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_17b():
    metadata_url = 'file://tests/metadata/cie/4.17b.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_18():
    metadata_url = 'file://tests/metadata/cie/4.18.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_AssertionConsumerService()
    assert md.errors


def test_cie_metadata_4_19():
    metadata_url = 'file://tests/metadata/cie/4.19.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_2():
    metadata_url = 'file://tests/metadata/cie/4.2.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_20():
    metadata_url = 'file://tests/metadata/cie/4.20.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_AssertionConsumerService()
    assert md.errors


def test_cie_metadata_4_21():
    metadata_url = 'file://tests/metadata/cie/4.21.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_22():
    metadata_url = 'file://tests/metadata/cie/4.22.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_3():
    metadata_url = 'file://tests/metadata/cie/4.3.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_4():
    metadata_url = 'file://tests/metadata/cie/4.4.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_5():
    metadata_url = 'file://tests/metadata/cie/4.5.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_6():
    metadata_url = 'file://tests/metadata/cie/4.6.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_7():
    metadata_url = 'file://tests/metadata/cie/4.7.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_8a():
    metadata_url = 'file://tests/metadata/cie/4.8a.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_8b():
    metadata_url = 'file://tests/metadata/cie/4.8b.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_9a():
    metadata_url = 'file://tests/metadata/cie/4.9a.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4_9b():
    metadata_url = 'file://tests/metadata/cie/4.9b.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_4():
    metadata_url = 'file://tests/metadata/cie/4.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_5_2():
    metadata_url = 'file://tests/metadata/cie/5.2.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_Organization()
    assert not md.errors


def test_cie_metadata_5():
    metadata_url = 'file://tests/metadata/cie/5.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_1():
    metadata_url = 'file://tests/metadata/cie/6.1.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_10a():
    metadata_url = 'file://tests/metadata/cie/6.10a.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_10b():
    metadata_url = 'file://tests/metadata/cie/6.10b.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_11a():
    metadata_url = 'file://tests/metadata/cie/6.11a.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_11b():
    metadata_url = 'file://tests/metadata/cie/6.11b.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_12a():
    metadata_url = 'file://tests/metadata/cie/6.12a.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_12b():
    metadata_url = 'file://tests/metadata/cie/6.12b.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_13a():
    metadata_url = 'file://tests/metadata/cie/6.13a.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_13b():
    metadata_url = 'file://tests/metadata/cie/6.13b.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_14a():
    metadata_url = 'file://tests/metadata/cie/6.14a.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_14b():
    metadata_url = 'file://tests/metadata/cie/6.14b.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    # <md:Company>Istituto Service Provider</md:Company>
	# <md:Company>Istituto Service Provider</md:Company>
    assert md.errors


def test_cie_metadata_6_15a():
    metadata_url = 'file://tests/metadata/cie/6.15a.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_contactperson_email(contact_type="technical")
    assert not md.errors


def test_cie_metadata_6_15b():
    metadata_url = 'file://tests/metadata/cie/6.15b.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_contactperson_email(contact_type="administrative")
    md.test_contactperson_email(contact_type="technical")
    assert not md.errors


def test_cie_metadata_6_17():
    metadata_url = 'file://tests/metadata/cie/6.17.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_Contacts_IPACode()
    assert not md.errors

# TODO fails after spid sogg ag private
# def test_cie_metadata_6_18():
    # metadata_url = 'file://tests/metadata/cie/6.18.xml'
    # md = get_md_check(metadata_url, **md_kwargs)
    # md.test_Contacts_VATFC()
    # assert md.errors


# def test_cie_metadata_6_19():
    # metadata_url = 'file://tests/metadata/cie/6.19.xml'
    # md = get_md_check(metadata_url, **md_kwargs)
    # md.test_Contacts_VATFC()
    # assert md.errors


# TODO
def test_cie_metadata_6_2():
    metadata_url = 'file://tests/metadata/cie/6.2.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_Contacts_PubPriv()
    assert md.errors

# TODO
def test_cie_metadata_6_20():
    metadata_url = 'file://tests/metadata/cie/6.20.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_extensions_cie()
    assert not md.errors

# TODO
def test_cie_metadata_6_21():
    metadata_url = 'file://tests/metadata/cie/6.21.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_extensions_cie()
    assert not md.errors


# TODO
def test_cie_metadata_6_22():
    metadata_url = 'file://tests/metadata/cie/6.22.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_extensions_cie()
    assert not md.errors

# TODO
def test_cie_metadata_6_23():
    metadata_url = 'file://tests/metadata/cie/6.23.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_extensions_cie()
    assert not md.errors


# TODO
def test_cie_metadata_6_25():
    metadata_url = 'file://tests/metadata/cie/6.25.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_contactperson_email()
    assert md.errors


def test_cie_metadata_6_3a():
    metadata_url = 'file://tests/metadata/cie/6.3a.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_Contacts_PubPriv()
    assert md.errors


def test_cie_metadata_6_3b():
    metadata_url = 'file://tests/metadata/cie/6.3b.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_Contacts_PubPriv()
    assert md.errors


def test_cie_metadata_6_3c():
    metadata_url = 'file://tests/metadata/cie/6.3c.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_Contacts_PubPriv()
    assert md.errors


def test_cie_metadata_6_3d():
    metadata_url = 'file://tests/metadata/cie/6.3d.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_Contacts_PubPriv()
    assert md.errors


def test_cie_metadata_6_3e():
    metadata_url = 'file://tests/metadata/cie/6.3e.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.test_Contacts_PubPriv()
    assert md.errors


def test_cie_metadata_6_4():
    metadata_url = 'file://tests/metadata/cie/6.4.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_5():
    metadata_url = 'file://tests/metadata/cie/6.5.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_6a():
    metadata_url = 'file://tests/metadata/cie/6.6a.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_6b():
    metadata_url = 'file://tests/metadata/cie/6.6b.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_7a():
    metadata_url = 'file://tests/metadata/cie/6.7a.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_7b():
    metadata_url = 'file://tests/metadata/cie/6.7b.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_8a():
    metadata_url = 'file://tests/metadata/cie/6.8a.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_8b():
    metadata_url = 'file://tests/metadata/cie/6.8b.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_9a():
    metadata_url = 'file://tests/metadata/cie/6.9a.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6_9b():
    metadata_url = 'file://tests/metadata/cie/6.9b.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors


def test_cie_metadata_6():
    metadata_url = 'file://tests/metadata/cie/6.xml'
    md = get_md_check(metadata_url, **md_kwargs)
    md.xsd_check()
    assert not md.errors
