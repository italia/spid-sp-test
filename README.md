spid-sp-test
------------

![CI build](https://github.com/italia/spid-sp-test/workflows/spid-sp-test/badge.svg)
![License](https://img.shields.io/badge/license-EUPL%201.2-blue)
![Python version](https://img.shields.io/badge/python-3.7%20%7C%203.8%20%7C%203.9-blue.svg)

spid-sp-test is a SAML2 SPID Service Provider validation tool that can be executed from the command line.
This tool was born by separating the test library already present in [spid-saml-check](https://github.com/italia/spid-saml-check).


Features
--------

spid-sp-test is:

- able to test a SAML2 SPID Metadata file or http url
- able to test a SAML2 SPID AuthnRequest file or or http url
- able to test ACS behaviour, how a SP replies to a SAML2 Response
- able to dump the responses sent to an ACS and the HTML of the SP's response
- able to handle Attributes to send in Responses or test configurations of the Responses via json configuration files
- able to configure response template with Jinja2
- able to get new test-suite via multiple json files
- fully integrable in CI
- able to export a detailed report in json format, in stdout or in a file

Generally it's:

- extremely faster in execution time than spid-saml-check
- extremely easy to setup

![example](gallery/example2.gif)

Setup
-----

````
apt install libxml2-dev libxmlsec1-dev libxmlsec1-openssl
pip install spid-sp-test --upgrade --no-cache
````

Overview
--------

spid-sp-test can test a SP metadata file, you just have to give the Metadata URL, if http/http or file, eg: `file://path/to/metadata.xml`.
At the same way it can test an Authentication Request.

In a different manner spid-sp-test can send a huge numer of fake SAML Response, for each of them it needs to trigger a real Authentication Request to the target SP.

If you want to test also the Response, you must give the spid-sp-test fake idp metadata xml file to the target SP.
Get fake IdP metadata (`--idp-metadata`) and copy it to your SP metadatastore folder.

````
spid_sp_test --idp-metadata > /path/to/spid-django/example/spid_config/metadata/spid-sp-test.xml
````

To get spid-sp-test in a CI you have to:

- configure an example project to your application
- use the spid-sp-test fake idp metadata, configure it in your application and execute the example project, with its development server in background
- launch the spid-sp-test commands

An example of CI [is here](https://github.com/italia/spid-django/blob/6baa2fe54a78c06193ffc5cd3f5c29a43b499232/.github/workflows/python-app.yml#L64)


Examples
--------

Run `spid_sp_test -h` for inline documentation.

````
usage: spid_sp_test [-h] [--metadata-url METADATA_URL] [--idp-metadata] [-l [LIST [LIST ...]]] [--extra] [--authn-url AUTHN_URL] [-tr] [-nsr] [-tp TEMPLATE_PATH] [-tn [TEST_NAMES [TEST_NAMES ...]]]
                    [-tj [TEST_JSONS [TEST_JSONS ...]]] [-aj ATTR_JSON] [-report] [-o O] [-d {CRITICAL,ERROR,WARNING,INFO,DEBUG}] [-xp XMLSEC_PATH] [--production] [--html-path HTML_PATH] [--exit-zero]

src/spid_sp_test/spid_sp_test -h for help

optional arguments:
  -h, --help            show this help message and exit
  --metadata-url METADATA_URL
                        URL where SAML2 Metadata resides: it can be file://path or https://fqdn
  --idp-metadata        get example IdP metadata
  -l [LIST [LIST ...]], --list [LIST [LIST ...]]
                        esecute only selected checks
  --extra               execute extra checks
  --authn-url AUTHN_URL
                        URL where the SP initializes the Authentication Request to this IDP,it can also be a file:///
  -tr, --test-response  execute SAML2 responses
  -nsr, --no-send-response
                        print SAML2 Response without sending back to SP. It only works with '-tr'
  -tp TEMPLATE_PATH, --template-path TEMPLATE_PATH
                        templates containing SAML2 xml templates for response tests
  -tn [TEST_NAMES [TEST_NAMES ...]], --test-names [TEST_NAMES [TEST_NAMES ...]]
                        response test to be executed, eg: 01 02 03
  -tj [TEST_JSONS [TEST_JSONS ...]], --test-jsons [TEST_JSONS [TEST_JSONS ...]]
                        custom test via json file, eg: tests/example.test-suite.json
  -aj ATTR_JSON, --attr-json ATTR_JSON
                        loads user attributes via json, eg: tests/example.attributes.json
  -report               json report in stdout
  -o O                  json report to file, -report is required
  -d {CRITICAL,ERROR,WARNING,INFO,DEBUG}, --debug {CRITICAL,ERROR,WARNING,INFO,DEBUG}
                        Debug level, see python logging
  -xp XMLSEC_PATH, --xmlsec-path XMLSEC_PATH
                        xmlsec1 executable path, eg: /usr/bin/xmlsec1
  --production, -p      execute tests for system in production, eg: https and TLS quality
  --html-path HTML_PATH, -hp HTML_PATH
                        Only works with Response tests activated. Path where the html response pages will be dumped after by the SP
  --exit-zero, -ez      exit with 0 even if tests fails

examples:
        src/spid_sp_test/spid_sp_test --metadata-url file://metadata.xml
        src/spid_sp_test/spid_sp_test --metadata-url http://localhost:8000/spid/metadata --extra
        src/spid_sp_test/spid_sp_test --metadata-url http://localhost:8000/spid/metadata -l test_Organization test_Signature

        # export idp metadata
        src/spid_sp_test/spid_sp_test --idp-metadata

        # test an authentication request made by a SP
        src/spid_sp_test/spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=spid-idp-test

        # select which tests to execute
        src/spid_sp_test/spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8080 --extra --debug ERROR -json -l xsd_check

        # execute Response tests
        src/spid_sp_test/spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8080 --extra --debug ERROR -tr

        # select which response test to execute
        src/spid_sp_test/spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8080 --extra --debug INFO -tr -tn 1 8 9 24 63

        # run a test suite configured in a json file
        src/spid_sp_test/spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8080 --extra --debug INFO -tr -tj tests/example.test-suite.json

        # select which user attribute to return in response via json file
        src/spid_sp_test/spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8080 --extra --debug DEBUG -aj tests/example.attributes.json

        # dump SP response as html page
        src/spid_sp_test/spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8080 --extra --debug ERROR -tr --html-path dumps

````


Test metadata passing a file
````
spid_sp_test --metadata-url file://metadata.xml
````

Test metadata from a URL
````
spid_sp_test --metadata-url http://localhost:8000/spid/metadata
````

A quite standard test
````
spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8088 --extra
````

Print only ERRORs
````
spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8080 --extra --debug ERROR
````

JSON report, add `-o filename.json` to write to a file, `-rf html -o html_report/` to export to a HTML page
````
spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8080 --extra --debug CRITICAL -json
````



Given a metadata file and a authn file (see `tests/metadata` and `tests/authn` for example) export all the test response without sending them to SP:

````
spid_sp_test --metadata-url file://tests/metadata/spid-django-other.xml --authn-url file://tests/authn/spid_django_post.html --extra --debug ERROR -tr -nsr
````

Get the response (test 1) that would have to be sent to a SP with a custom set of attributes, without sending it for real. It will just print it to stdout

````
spid_sp_test --metadata-url file://tests/metadata/spid-django-other.xml --authn-url file://tests/authn/spid_django_post.html --extra --debug ERROR -tr -nsr -tn 1 -aj tests/example.attributes.json

````


Test Responses and html dumps
-----------------------------

By enabling the response dump with the `--html-path HTML_PATH` option, you will get N html files (page of your SP) as follows:


- test description, commented
- SAML Response sent, commented
- SP html page, with absolute src and href (god bless lxml)

Here an example of **1_True.html**, where `1` is the test name and `True` is the status.

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

Extending tests
---------------

spid-sp-test offers the possibility to extend and configure new response tests to be performed. The user can:

- customize the test suite to run by configuring a json file similar to
  `tests/example.test-suite.json` and passing this as an argument with
  `--test-jsons` option. More than one json file can be entered by separating it by a space

- customize the attributes to be returned by configuring these in a json file similar to
  `example/example.attributes.json` and passing this with the `--attr-json` option

- customize xml templates to be used in tests, indicating them in each
  test entry in the configuration file configured via `--test-jsons`
  and also the templates directory with the option `--template-path`.
  The templates are Jinja2 powered, so it's possible to
  extend `src/spid_sp_test/responses/templates/base.xml` with our preferred values

Looking at `src/spid_sp_test/responses/settings.py` or `tests/example.test-suite.json`
we found that every test have a `response` attribute. Each element configured in would overload the
value that will be rendered in the template. Each template can load these variable from its template context or
use which ones was statically defined in it.

Finally you have batteries included and some options as well, at your taste.

Unit tests
----------

That's for developers.

````
pip install requirements-dev.txt
pytest --cov=src/spid_sp_test tests/test_*
````


Authors
-------

- [Giuseppe De Marco](https://github.com/peppelinux)
- [Paolo Smiraglia](https://github.com/psmiraglia)
- [Michele D'Amico](https://github.com/damikael)


References
----------

TLS/SSL tests

- [https://github.com/nabla-c0d3/sslyze](https://github.com/nabla-c0d3/sslyze)
    ````
    pip install --upgrade sslyze
    sslyze www.that-sp.org --json_out ssl.log
    ````
- [https://testssl.sh/](https://testssl.sh/)
