````
<!-- Response corretta. Risultato atteso: Ok -->

<!-- <?xml version="1.0"?>
<samlp:Response xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost:8000/spid/acs/" ID="_mwmzlidj-fppt-jryt-kvfx-ulaxcbnzhhtk" InResponseTo="id-LeCCYOOGkYFrysiKZ" IssueInstant="2021-03-21T18:12:43Z" Version="2.0">
    <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://localhost:8080</saml:Issuer>


    <ds:Signature>
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <ds:Reference URI="#_mwmzlidj-fppt-jryt-kvfx-ulaxcbnzhhtk">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>7+hvbXYS5rczc1fDOD4YTnP7QzEBfaSq2LGrkQSg0yI=</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>DJSOgjXJ0OrU1pgIhiv9EiI/zMDaZExcRtUSSz+2swpM9d/lQssgOxQ1wSRRD7jn
2CS4k8x7x9m92qQRIAUwXz4CScU3LVdH9/CJKPf1E0SDE7ENPlApQ6csi7USJpRL
h7lERyocGiPTsC1HbGs9AqZP+zVSenbMgmbLLidb2c9rdlzYLjm5leOG+qtec4jT
TeMEM0WGdC2iCZKJvp6Bahmpl5QrhADRad8g2ulwW2cJpB5CjRkpjtnLr+LAE/OV
CbfWzhUY3k9NiO1OE5nIqLNCW2iwe5+m8IrO5dstcFAhcNlF+/pkTvX+xnX2w7A4
HVBC/yGuGdm7iksopV0WoA==</ds:SignatureValue>
    </ds:Signature>

    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>


    <saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="_zpyvhqej-suvh-oekc-zvtt-iocdveoergib" IssueInstant="2021-03-21T18:12:43Z" Version="2.0">



    <ds:Signature>
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <ds:Reference URI="#_zpyvhqej-suvh-oekc-zvtt-iocdveoergib">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue>dmd5Axp3vXNJmgOgBgfuhflWGb8wx6o2VoFeb8as35Q=</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>HYfbyTCQzc/EIGEahYM9HenARSRpob3xiqUWFtQ6c9XVmznHAQgmAc/VvW5TQUWQ
b6JSPQsS6zp2/LClKXFAdka8sFV7qnz3C0Jbjc0AkeBoiMJqOcImGC1tLRNQ2j/w
JEMGnPoVDxTfsgUwYM1PWNKtnJ21Z+1G5ZFK6MsWUVpnB/NT6nDajmT5JLrqPMhb
p3Qstbfjmm4ZENfTGXdWshgZHR8qx0VRLJx1TgoSMJG0g6AyYFV6k/Xm6MCo7SOA
SWyL+3IsBJSz1rpOKZ8n2Lbo3L6z9zwexIsMklsVFq1VcNbEbtelwMAiVLRELbj8
/dM70O4D51WtO1fTr5T5CA==</ds:SignatureValue>
    </ds:Signature>

        <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://localhost:8080</saml:Issuer>

        <saml:Subject>

            <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" NameQualifier="http://localhost:8080">
                    that-transient-opaque-value
            </saml:NameID>


            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData InResponseTo="id-LeCCYOOGkYFrysiKZ" NotOnOrAfter="2021-03-21T18:17:43Z" Recipient="http://localhost:8000/spid/acs/"/>
            </saml:SubjectConfirmation>

        </saml:Subject>


        <saml:Conditions NotBefore="2021-03-21T18:12:43Z" NotOnOrAfter="2021-03-21T18:17:43Z">

            <saml:AudienceRestriction>
                <saml:Audience>http://localhost:8000/spid/metadata</saml:Audience>
            </saml:AudienceRestriction>

        </saml:Conditions>


        <saml:AuthnStatement AuthnInstant="2021-03-21T18:12:43Z" SessionIndex="_kyfjbqds-zbgy-nfhj-ewse-iqaddsdczdjd">

            <saml:AuthnContext>
                <saml:AuthnContextClassRef>https://www.spid.gov.it/SpidL1</saml:AuthnContextClassRef>
            </saml:AuthnContext>

        </saml:AuthnStatement>


        <saml:AttributeStatement>

    <saml:Attribute Name="spidCode">
    <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">AGID-001</saml:AttributeValue>
    </saml:Attribute>

    <saml:Attribute Name="name">
    <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">SpidValidator</saml:AttributeValue>
    </saml:Attribute>

    <saml:Attribute Name="familyName">
    <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">AgID</saml:AttributeValue>
    </saml:Attribute>

    <saml:Attribute Name="placeOfBirth">
    <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Roma</saml:AttributeValue>
    </saml:Attribute>

    <saml:Attribute Name="countyOfBirth">
    <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">RM</saml:AttributeValue>
    </saml:Attribute>

    <saml:Attribute Name="dateOfBirth">
    <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:date">2000-01-01</saml:AttributeValue>
    </saml:Attribute>

    <saml:Attribute Name="gender">
    <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">M</saml:AttributeValue>
    </saml:Attribute>

    <saml:Attribute Name="companyName">
    <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Agenzia per l'Italia Digitale</saml:AttributeValue>
    </saml:Attribute>

    <saml:Attribute Name="registeredOffice">
    <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">Via Listz 21 00144 Roma</saml:AttributeValue>
    </saml:Attribute>

    <saml:Attribute Name="fiscalNumber">
    <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">TINIT-GDASDV00A01H501J</saml:AttributeValue>
    </saml:Attribute>

        </saml:AttributeStatement>

    </saml:Assertion>

</samlp:Response>
 -->

<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
  <head>

  </head>
  <body>
    <h1>SAML attributes</h1>
    <dl>

      <dt>spidCode:</dt>
      <dd>AGID-001</dd>

      <dt>name:</dt>
      <dd>SpidValidator</dd>

      <dt>familyName:</dt>
      <dd>AgID</dd>

      <dt>placeOfBirth:</dt>
      <dd>Roma</dd>

      <dt>countyOfBirth:</dt>
      <dd>RM</dd>

      <dt>dateOfBirth:</dt>
      <dd>2000-01-01</dd>

      <dt>gender:</dt>
      <dd>M</dd>

      <dt>companyName:</dt>
      <dd>Agenzia per l'Italia Digitale</dd>

      <dt>registeredOffice:</dt>
      <dd>Via Listz 21 00144 Roma</dd>

      <dt>fiscalNumber:</dt>
      <dd>TINIT-GDASDV00A01H501J</dd>

    </dl>

    <p><a href="http://localhost:8000/spid/logout/">Log out</a></p>
  </body>
</html>
````
