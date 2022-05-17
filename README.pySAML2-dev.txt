a = """<?xml version="1.0"?>
<spid:Extensions xmlns:spid="https://www.spid.gov.it/saml-extensions">
<spid:ContactPerson contactType="other">
 <spid:Extensions xmlns:spid="https://www.spid.gov.it/saml-extensions">
 <spid:VATNumber>IT12345678901</spid:VATNumber>
 <spid:FiscalCode>XYZABCAAMGGJ000W</spid:FiscalCode>
 <spid:Private/>
 </spid:Extensions>
 <spid:EmailAddress>spid@organizzazione.com</spid:EmailAddress>
 <spid:TelephoneNumber>+390123456789</spid:TelephoneNumber>
</spid:ContactPerson>
"""

from saml2.md import *

SPID_PREFIXES = dict(md = 'urn:oasis:names:tc:SAML:2.0:metadata',
                     spid = "https://www.spid.gov.it/saml-extensions")
SamlBase.register_prefix(SPID_PREFIXES)

d = """<?xml version='1.0' encoding='UTF-8'?>
<md:EntityDescriptor entityID="https://entityID.unico/dell/SP" 
                     ID="_uniqueID" 
                     xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" 
                     xmlns:spid="https://spid.gov.it/saml-extensions">
 
<md:Extensions xmlns:spid="https://www.spid.gov.it/saml-extensions">
 <spid:VATNumber>IT12345678901</spid:VATNumber>
 <spid:FiscalCode>XYZABCAAMGGJ000W</spid:FiscalCode>
 <spid:Private/>
</md:Extensions>
</md:EntityDescriptor>"""

spid_ext = saml2.extension_element_from_string(d)
print(spid_ext.to_string().decode())




# AVVISO 29 v3

e = """<?xml version='1.0' encoding='UTF-8'?>
<md:ContactPerson contactType="other">
 <md:EmailAddress>spid@organizzazione.com</md:EmailAddress>
 <md:TelephoneNumber>+390123456789</md:TelephoneNumber>
</md:ContactPerson>"""

spid_ext = saml2.extension_element_from_string(e)
spid_ext.to_string()




####################

SPID_PREFIXES = dict(spid = "https://www.spid.gov.it/saml-extensions")
SamlBase.register_prefix(SPID_PREFIXES)

spid_extensions = Extensions()
spid_extensions.c_namespace = "https://spid.gov.it/saml-extensions"

spid_extensions = saml2.ExtensionElement('Extensions', 
                                         namespace="https://www.spid.gov.it/saml-extensions")
spid_extensions.to_string()

SPID_CONTACT_PERSON_DICT = {
    'VATNumber': 'IT12345678901',
    'FiscalCode': 'XYZABCAAMGGJ000W',
    'Private': ''
}

for k,v in SPID_CONTACT_PERSON_DICT.items():
    ext = saml2.ExtensionElement(k, 
                                 namespace="https://www.spid.gov.it/saml-extensions",
                                 text=v)
    spid_extensions.children.append(ext)

spid_extensions.to_string()
