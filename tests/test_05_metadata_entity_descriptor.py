import pytest

from . import get_md_check
from . import load_metadata


def test_metadata_xsd():
    metadata_url = 'file://tests/metadata/spid-django-other.xml'
    md = get_md_check(metadata_url)
    md.xsd_check()
    assert not md.errors


def test_metadata_entity_descriptor_ok():
    metadata = b"""<md:EntityDescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:spid="https://spid.gov.it/saml-extensions" entityID="https://localhost:8000/spid/metadata/" ID="id-SKWJbXNIQ9Za23Xkk">
        <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true" WantAssertionsSigned="true">
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://localhost:8000/spid/ls/post/"/>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://localhost:8000/spid/acs/" index="0" isDefault="true"/>
        <md:AttributeConsumingService index="0">
        <md:ServiceName xml:lang="it">https://localhost:8000/spid/metadata/</md:ServiceName><md:RequestedAttribute Name="spidCode" isRequired="true"/>
        <md:RequestedAttribute Name="name" isRequired="true"/>
        <md:RequestedAttribute Name="familyName" isRequired="true"/>
        <md:RequestedAttribute Name="fiscalNumber" isRequired="true"/>
        <md:RequestedAttribute Name="email" isRequired="true"/>
        <md:RequestedAttribute Name="gender" isRequired="false"/>
        <md:RequestedAttribute Name="companyName" isRequired="false"/>
        <md:RequestedAttribute Name="registeredOffice" isRequired="false"/>
        <md:RequestedAttribute Name="ivaCode" isRequired="false"/>
        <md:RequestedAttribute Name="idCard" isRequired="false"/>
        <md:RequestedAttribute Name="digitalAddress" isRequired="false"/>
        <md:RequestedAttribute Name="placeOfBirth" isRequired="false"/>
        <md:RequestedAttribute Name="countyOfBirth" isRequired="false"/>
        <md:RequestedAttribute Name="dateOfBirth" isRequired="false"/>
        <md:RequestedAttribute Name="address" isRequired="false"/>
        <md:RequestedAttribute Name="mobilePhone" isRequired="false"/>
        <md:RequestedAttribute Name="expirationDate" isRequired="false"/>
        </md:AttributeConsumingService>
        </md:SPSSODescriptor>
        <md:Organization>
            <md:OrganizationName xml:lang="it">Example</md:OrganizationName>
            <md:OrganizationName xml:lang="en">Example</md:OrganizationName>
            <md:OrganizationDisplayName xml:lang="it">Example</md:OrganizationDisplayName>
            <md:OrganizationDisplayName xml:lang="en">Example</md:OrganizationDisplayName>
            <md:OrganizationURL xml:lang="it">http://www.example.it</md:OrganizationURL>
            <md:OrganizationURL xml:lang="en">http://www.example.it</md:OrganizationURL>
        </md:Organization>
        <md:ContactPerson contactType="other">
            <md:Extensions>
                <spid:IPACode>that-IPA-code</spid:IPACode>
                <spid:VATNumber>IT12345678901</spid:VATNumber>
                <spid:FiscalCode>XYZABCAAMGGJ000W</spid:FiscalCode>
                <spid:Public/>
                </md:Extensions>
            <md:EmailAddress>tech-info@example.org</md:EmailAddress>
            <md:TelephoneNumber>+398475634785</md:TelephoneNumber>
        </md:ContactPerson></md:EntityDescriptor>
    """

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
