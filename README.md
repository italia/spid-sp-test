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

Test metadata passing a file
````
spid_sp_test -metadata_url file://metadata.xml
````

Test metadata from a URL
````
spid_sp_test -metadata_url http://localhost:8000/spid/metadata
````

Get fake IdP metadata and copy it to your SP metadatastore folder
````
spid_sp_test --idp-metadata > /path/to/spid-django/example/spid_config/metadata/spid-sp-test.xml
````

A quite standard test
````
spid_sp_test -metadata_url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8088 --extra
````

Print only ERRORs
````
spid_sp_test -metadata_url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8080 --extra -debug ERROR
````

JSON report (add `-o filename.json` to write to a file)
````
spid_sp_test -metadata_url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8080 --extra -debug CRITICAL -json
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
- [https://testssl.sh/](https://testssl.sh/)
