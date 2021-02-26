spid-sp-test
------------
spid-test-env is a SAML2 SPID Service Provider validation tool that can be run from the command line.
This tool was born by separating the test library already present in [spid-saml-check](https://github.com/italia/spid-saml-check).


#### Features

spid-sp-test is:

- extremely faster in execution time than spid-saml-check
- extremely easy to setup
- able to test a SAML2 SPID Metadata file
- able to test a SAML2 SPID AuthnRequest
- integrable in CI
- able to export a fully detailed report in json format, in stdout or in a file


#### Roadmap

A hunderd of SAML2 SPID fake Responses ... For security assessment!


Setup
-----

````
apt install libxml2-dev libxmlsec1-dev libxmlsec1-openssl
pip install spid-sp-test --upgrade --no-cache
````

Examples
--------

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

A more complex test
````
spid_sp_test -metadata_url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8088 --extra -debug DEBUG
````

Print only ERRORs
````
spid_sp_test -metadata_url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8080 --extra -debug ERROR
````

JSON report (add `-o filename.json` to write to a file)
````
python3 src/spid_sp_test/spid_sp_test -metadata_url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8080 --extra -debug CRITICAL -json
````


Authors
-------

- Giuseppe De Marco
- Paolo Smiraglia
- Michele D'Amico
