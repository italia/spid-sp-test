import pytest

from . import UNSIGNED_METADATA
from . import get_md_check
from . import load_metadata



def test_metadata_xsd():
    metadata_url = 'file://tests/metadata/spid-django-other_signed.xml'
    md = get_md_check(metadata_url)
    md.xsd_check()
    assert not md.errors


def test_metadata_entity_descriptor_ok():
    metadata = UNSIGNED_METADATA

    md = load_metadata(metadata)
    md.test_EntityDescriptor()
    assert not md.errors


def test_metadata_entity_descriptor_absent():
    metadata = b""
    with pytest.raises(Exception):
        md = load_metadata(metadata)


def test_metadata_entity_descriptor_double():
    metadata = b"""<md:EntityDescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:spid="https://spid.gov.it/saml-extensions" entityID="https://localhost:8000/spid/metadata/" ID="id-SKWJbXNIQ9Za23Xkk"></md:EntityDescriptor>
    <md:EntityDescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:spid="https://spid.gov.it/saml-extensions" entityID="https://localhost:8000/spid/metadata/" ID="id-SKWJbXNIQ9Za23Xkk"></md:EntityDescriptor>"""
    with pytest.raises(Exception):
        md = load_metadata(metadata)


def test_metadata_entity_descriptor_unvalued_eid():
    metadata = b"""<md:EntityDescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:spid="https://spid.gov.it/saml-extensions" entityID="" ID="id-SKWJbXNIQ9Za23Xkk"></md:EntityDescriptor>"""
    md = load_metadata(metadata)
    md.test_EntityDescriptor()
    assert md.errors[0]['test'] == 'The entityID attribute MUST be present'


def test_metadata_entity_descriptor_no_eid():
    metadata = b"""<md:EntityDescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:spid="https://spid.gov.it/saml-extensions"
    ID="id-SKWJbXNIQ9Za23Xkk"></md:EntityDescriptor>"""
    md = load_metadata(metadata)
    md.test_EntityDescriptor()
    assert md.errors[1]['test'] == "The entityID attribute MUST have a value"


def test_metadata_entity_descriptor_production_eid():
    metadata = b"""<md:EntityDescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:spid="https://spid.gov.it/saml-extensions" entityID="sdfsdfsdfsdfsdfsdfsfsdfsdf" ID="id-SKWJbXNIQ9Za23Xkk"></md:EntityDescriptor>"""
    md = load_metadata(metadata, production=True)
    md.test_EntityDescriptor()
    assert md.errors[0]['test'] == "The entityID attribute MUST be a valid HTTPS url"


def test_metadata_entity_descriptor_production_noport():
    metadata = b"""<md:EntityDescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:spid="https://spid.gov.it/saml-extensions" entityID="https://ciao.it:8000" ID="id-SKWJbXNIQ9Za23Xkk"></md:EntityDescriptor>"""
    md = load_metadata(metadata, production=True)
    md.test_EntityDescriptor()
    assert md.errors[0]['test'] == 'The entityID attribute MUST not contains any custom tcp ports, eg: ":8000"'
