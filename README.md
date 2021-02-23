spid-sp-test
------------

introduction

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
python3 spid_sp_test -metadata_url file://metadata.xml
````

Test metadata from a URL
````
python3 spid_sp_test -metadata_url http://localhost:8000/spid/metadata
````

