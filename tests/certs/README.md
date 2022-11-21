### public


```
spid-compliant-certificates generator --key-size 3072 --common-name "spid-sp-test" --days 7650 --entity-id https://spid.example.it --locality-name Roma --org-id "PA:IT-c_h501" --org-name "Developers Italia" --sector public

cat crt.pem > ../pub_crt.pem 
cat key.pem > ../pub_key.pem 

```

### private

```
spid-compliant-certificates generator --key-size 3072 --common-name "spid-sp-test" --days 7650 --entity-id https://spid.example.it --locality-name Roma --org-id "VATIT-12345678901" --org-name "Developers Italia" --sector private


cat crt.pem > ../priv_crt.pem 
cat key.pem > ../priv_key.pem 

```
