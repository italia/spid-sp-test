````
export SSLLABS_SKIP=1 

export DATA_DIR=./data/http___sp1_testunical_it_8000_saml2_metadata_ 
export SP_METADATA=./data/http___sp1_testunical_it_8000_saml2_metadata_/sp-metadata.xml
export SP_METADATA=data/https___172_17_0_1_10000_spidSaml2_metadata/sp-metadata.xml

export AUTHN_REQUEST=./data/http___sp1_testunical_it_8000_saml2_metadata_/authn-request.xml

cd ~/DEV/DTD/Spid/spid-saml-check/specs-compliance-tests
source .env/bin/activate


# messo da parte: metadata_xsd_ag.py -> errore validazione extensions come PR su spid Contacts elements ...
# messo da parte: test/sp/metadata_ficep_strict.py
#    [FAIL] Must be present an AttributeConsumingService with index = 99 - AV eIDAS n° 1
#    [FAIL] Must be present an AttributeConsumingService with index = 99 and the sub-elemenet ServiceName vith "eIDAS Natural Person Minimum Attribute Set" value - AV eIDAS n° 1
#    [FAIL] The Name attribute in RequestedAttribute element must be one of [spidCode, name, familyName, dateOfBirth] 

python -m unittest --verbose  test/sp/metadata_certs.py test/sp/metadata_extra.py test/sp/metadata_strict.py test/sp/metadata_xsd_sp.py test/sp/metadata_xsd_sp-av29.py

for i in `ls test/sp/metadata*`; do printf "\nTesting %s\n" $i; python -m unittest --verbose $i; done

url = "https://172.17.0.1:10000/spidSaml2/metadata"

import re
def create_folder_name(url):
   re.sub(r'[:/.]', '_', url)


#########################

# pip install xmlschema xsdata
import xmlschema
import os

BASE_DIR = '/home/wert/DEV/DTD/Spid/spid-saml-check/specs-compliance-tests'
XSD_DIR = f'{BASE_DIR}/xsd'
os.chdir(XSD_DIR)

SP_METADATA=f'{BASE_DIR}/data/http___sp1_testunical_it_8000_saml2_metadata_/sp-metadata.xml'
SP_METADATA=f'{BASE_DIR}/data/http___sp1_testunical_it_8000_saml2_metadata_/sp-metadata.xml'

xsd_test_files = [
                  # 'saml-schema-assertion-2.0.xsd',
                  'saml-schema-metadata-2.0.xsd',
                  #'saml-schema-metadata-aggregated-spid.xsd',
                  'saml-schema-metadata-sp-spid-av29.xsd',
                  'saml-schema-metadata-sp-spid.xsd',
                  # 'saml-schema-protocol-2.0.xsd',
                  # 'spid-invoicing.xsd',
                  # 'spid.xsd',
                  # 'xenc-schema.xsd',
                  #'xmldsig-core-schema.xsd',
                  # 'xml.xsd'
]


for testf in xsd_test_files:
    testf_path = f'{XSD_DIR}/{testf}'
    schema_file = open(testf_path)
    print(f'Processing {testf_path} with {schema_file.name}')
    schema = xmlschema.XMLSchema(schema_file)
    if not schema.is_valid(SP_METADATA):
        schema.validate(SP_METADATA)
        raise Exception('Validation Error')

####################

riusare il codice degli unit test inline
cd /home/wert/DEV/DTD/Spid/spid-saml-check/specs-compliance-tests/
export SP_METADATA=data/https___172_17_0_1_10000_spidSaml2_metadata/sp-metadata.xml
ipython

import json
import os
import sys

sys.path.append('/home/wert/DEV/DTD/Spid/spid-saml-check/specs-compliance-tests')
DATA_DIR = os.getenv('DATA_DIR', './data')


os.chdir('test')
from sp.metadata_strict import TestSPMetadata
t = TestSPMetadata()
os.chdir('..')
t.setUp()
t.test_xmldsig()

os.chdir('test')
from sp.metadata_xsd_sp_av29 import TestSPMetadataXSD
t = TestSPMetadataXSD()
os.chdir('..')
t.setUp()
t.test_xsd()
fname = '%s/sp-metadata-xsd-sp-av29.json' % DATA_DIR
result = json.loads(open(fname).read())
print(result)
````
