spid-sp-test
------------
spid-test-env is a SAML2 SPID Service Provider validation tool that can be run from the command line.


Setup
-----

````
apt install libxml2-dev libxmlsec1-dev libxmlsec1-openssl
pip install xmlsec
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
python3 src/spid_sp_test/spid_sp_test -metadata_url http://localhost:8000/spid/metadata --authn-url http://localhost:8000/spid/login/?idp=http://localhost:8080 --extra -debug ERROR -json
````
