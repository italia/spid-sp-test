# Metadata signature


````
xmlsec1 --sign --insecure --privkey-pem tests/certs/pub_key.pem --id-attr:ID urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor tests/metadata/spid-django-other.xml > tests/metadata/spid-django-other_signed.xml
````

## Public 

````
for i in `ls tests/metadata/*pub*_signed*`; \
do xmlsec1 --sign --insecure --privkey-pem tests/certs/pub_key.pem --id-attr:ID urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor `echo $i | sed -e s'/_signed//g'` > $i; \
done
````

Then substitute the public crt pem in all the occurences of `<ds:X509Certificate>` in the relating metadata.


## Private

````
for i in `ls tests/metadata/*pri*_signed*`; \
do xmlsec1 --sign --insecure --privkey-pem tests/certs/priv_key.pem --id-attr:ID urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor `echo $i | sed -e s'/_signed//g'` > $i; \
done
````

Then substitute the public crt pem in all the occurences of `<ds:X509Certificate>` in the relating metadata.


xmlsec1 --sign --insecure --privkey-pem tests/certs/pub_key.pem --id-attr:ID urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor tests/metadata/pub-ag-full.xml > tests/metadata/
