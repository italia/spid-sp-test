from spid_sp_test.authn_request_extra import SpidSpAuthnReqCheckExtra
from spid_sp_test.metadata_extra import SpidSpMetadataCheckExtra
from tempfile import NamedTemporaryFile


UNSIGNED_METADATA = b"""<md:EntityDescriptor xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:spid="https://spid.gov.it/saml-extensions" entityID="https://localhost:8000/spid/metadata/" ID="id-SKWJbXNIQ9Za23Xkk">
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

UNSIGNED_AUTHNREQ = b"""<samlp:AuthnRequest xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id-SnKShnfyySFgj04dH" Version="2.0" IssueInstant="2021-07-17T01:07:03Z" Destination="https://localhost:8080" ForceAuthn="false" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="https://localhost:8000/spid/acs/" AttributeConsumingServiceIndex="0">

<saml:Issuer NameQualifier="https://localhost:8000/spid/metadata/" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://localhost:8000/spid/metadata/</saml:Issuer>

<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>
<samlp:RequestedAuthnContext Comparison="minimum">
    <saml:AuthnContextClassRef>https://www.spid.gov.it/SpidL1</saml:AuthnContextClassRef>
</samlp:RequestedAuthnContext></samlp:AuthnRequest>
"""


def get_md_check(metadata_url, **kwargs):
    md = SpidSpMetadataCheckExtra(metadata_url=metadata_url, **kwargs)
    md.load()
    return md


def load_metadata(metadata, **kwargs):
    tmp_file = NamedTemporaryFile(suffix=".xml")
    tmp_file.write(metadata)
    tmp_file.seek(0)
    return get_md_check(f"file://{tmp_file.name}", **kwargs)


def get_authnreq_check(metadata, authn_request_url, **kwargs):
    ar = SpidSpAuthnReqCheckExtra(
        metadata=metadata, authn_request_url=authn_request_url, **kwargs
    )
    ar.load()
    return ar


def load_authnreq(metadata, authn_request_url, **kwargs):
    tmp_file = NamedTemporaryFile(suffix=".xml")
    tmp_file.write(authn_request_url)
    tmp_file.seek(0)
    return get_authnreq_check(metadata, f"file://{tmp_file.name}", **kwargs)
