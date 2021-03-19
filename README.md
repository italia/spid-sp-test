spid-sp-test
------------
spid-sp-test is a SAML2 SPID Service Provider validation tool that can be run from the command line.
This tool was born by separating the test library already present in [spid-saml-check](https://github.com/italia/spid-saml-check).


Features
--------

spid-sp-test is:

- extremely faster in execution time than spid-saml-check
- extremely easy to setup
- able to test a SAML2 SPID Metadata file
- able to test a SAML2 SPID AuthnRequest
- integrable in CI
- able to export a detailed report in json format, in stdout or in a file.

![example](gallery/example2.gif)


Roadmap
-------

- Next releases: a hundred of SAML2 SPID fake Responses ... For security assessment!

How to handle Http Response checks?

1. python `requests` and SAML2 needs to use a POST method to a ACS service. Then `requests` checks http status page in the HTTP response page, then saves HTML to a browsable folder for any further human analisys
2. selenium HQ -> very huge to be loaded in a CI!

it is possible to think of getting screenshots using selenium HQ but the use of selenium should be completely optional for the needs of CI.

Setup
-----

````
apt install libxml2-dev libxmlsec1-dev libxmlsec1-openssl
pip install spid-sp-test --upgrade --no-cache
````

Examples
--------

Run `spid_sp_test -h` for inline documentation.

````
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
  -tp TEMPLATE_PATH, --template-path TEMPLATE_PATH
                        templates containing SAML2 xml templates, for responses
  -tn [TEST_NAMES [TEST_NAMES ...]], --test-names [TEST_NAMES [TEST_NAMES ...]]
                        response test to be executed, eg: 01 02 03
  -tj [TEST_JSONS [TEST_JSONS ...]], --test-jsons [TEST_JSONS [TEST_JSONS ...]]
                        custom test via json file, eg: tests/example.test-suite.json
  -aj ATTR_JSON, --attr-json ATTR_JSON
                        loads user attributes via json, eg: tests/example.attributes.json
  -json                 json output
  -o O                  json output to file
  -d {CRITICAL,ERROR,WARNING,INFO,DEBUG}, --debug {CRITICAL,ERROR,WARNING,INFO,DEBUG}
                        Debug level, see python logging
  -xp XMLSEC_PATH, --xmlsec-path XMLSEC_PATH
                        xmlsec1 executable path, eg: /usr/bin/xmlsec1

examples:
        src/spid_sp_test/spid_sp_test --metadata-url file://metadata.xml
        src/spid_sp_test/spid_sp_test --metadata-url http://localhost:8000/spid/metadata --extra
        src/spid_sp_test/spid_sp_test --metadata-url http://localhost:8000/spid/metadata -l test_Organization test_Signature

        # export idp metadata
        src/spid_sp_test/spid_sp_test --idp-metadata

        # test an authentication request made by a SP
        src/spid_sp_test/spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=spid-idp-test

        # select which tests to execute
        src/spid_sp_test/spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8080 --extra -debug ERROR -json -l xsd_check

        # execute Response tests
        src/spid_sp_test/spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:54321 --extra -debug ERROR -tr

        # select which response test to execute
        src/spid_sp_test/spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:54321 --extra --debug INFO -tr -tn 1 8 9 24 63

        # run a test suite configured in a json file
        src/spid_sp_test/spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:54321 --extra --debug INFO -tr -tj tests/example.test-suite.json

        # select which user attribute to return in response via json file
        src/spid_sp_test/spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:54321 --extra --debug DEBUG -aj tests/example.attributes.json

````


Test metadata passing a file
````
spid_sp_test --metadata-url file://metadata.xml
````

Test metadata from a URL
````
spid_sp_test --metadata-url http://localhost:8000/spid/metadata
````

Get fake IdP metadata and copy it to your SP metadatastore folder
````
spid_sp_test --idp-metadata > /path/to/spid-django/example/spid_config/metadata/spid-sp-test.xml
````

A quite standard test
````
spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8088 --extra
````

Print only ERRORs
````
spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8080 --extra -debug ERROR
````

JSON report (add `-o filename.json` to write to a file)
````
spid_sp_test --metadata-url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8080 --extra -debug CRITICAL -json
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
