# Metadata signature


````
xmlsec1 --sign --insecure --privkey-pem src/spid_sp_test/idp/private.key --id-attr:ID urn:oasis:names:tc:SAML:2.0:metadata:EntityDescriptor tests/metadata/pub-ag-full.xml > tests/metadata/pub-ag-full_signed.xml
````
