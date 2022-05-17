# Metadata signature


````
xmlsec1 --sign --insecure --privkey-pem tests/certs/pub_key.pem --id-attr:ID urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor tests/metadata/pub-ag-full.xml > tests/metadata/pub-ag-full_signed.xml
````


Massive update (remember to put the right x509 certificates in the metadata file first!)

````
for i in `ls tests/metadata/*_signed*`; \
do xmlsec1 --sign --insecure --privkey-pem tests/certs/pub_key.pem --id-attr:ID urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor `echo $i | sed -e s'/_signed//g'` > $i; \
done
````

Mind that private entities MUST use `tests/certs/priv_key.pem`


