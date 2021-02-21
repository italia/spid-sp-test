import logging
import os
import requests
import xmlschema
import sys
import subprocess

from lxml import etree
from tempfile import NamedTemporaryFile

sys.path.append(os.path.join(os.path.dirname(__file__), os.pardir))
from spid_sp_test import BASE_DIR
from spid_sp_test.utils import del_ns

logger = logging.getLogger(__name__)


class SpidSpMetadataCheck(object):
    xsds_files = [
        'saml-schema-metadata-2.0.xsd',
        # 'saml-schema-metadata-sp-spid-av29.xsd',
        'saml-schema-metadata-sp-spid-av29_old.xsd',
        'saml-schema-metadata-sp-spid.xsd',
    ]

    def __init__(self, 
                 metadata_url, 
                 xsds_files:list = None,
                 xsds_files_path:str = None):

        self.metadata_url = metadata_url
        self.metadata = self.__class__.get(metadata_url)
        self.xsds_files = xsds_files or self.xsds_files
        self.xsds_files_path = xsds_files_path or f'{BASE_DIR}/xsd'
        
        self.doc = etree.fromstring(self.metadata)
        # clean up namespace (otherwise xpath doesn't work ...)
        del_ns(self.doc)
        
        
    @staticmethod
    def get(metadata_url:str):
        if metadata_url[0:7] == 'file://':
            return open(metadata_url[7:], 'rb').read()
        else:
            return requests.get(metadata_url).content
    
    
    def xsd_check(self):
        logger.debug(f'Found metadata: {self.metadata}')
        os.chdir(self.xsds_files_path)
        metadata = self.metadata.decode()
        for testf in self.xsds_files:
            schema_file = open(testf, 'rb')
            msg = f'Test {self.metadata_url} with {schema_file.name}'
            try:
                schema = xmlschema.XMLSchema(schema_file)
                if not schema.is_valid(metadata):
                    schema.validate(metadata)
                    logger.error(' '.join((msg, '-> FAILED!')))
                    raise Exception('Validation Error')
                logger.info(' '.join((msg, '-> OK')))
            except Exception as e:
                logger.critical('-> '.join((msg, f'{e}')))


    def test_EntityDescriptor(self):
        entity_desc = self.doc.xpath('//EntityDescriptor')
        if not self.doc.attrib.get('entityID'):
            logger.error(f'Missing entityID in {self.doc.attrib}: '
                          'The entityID attribute must be present - TR pag. 19')
        elif len(entity_desc) > 1:
            logger.error('Only one EntityDescriptor element must be present - TR pag. 19')

        elif not entity_desc[0].get('entityID'):
            logger.error('The entityID attribute must have a value - TR pag. 19')


    def test_SPSSODescriptor(self):
        spsso = self.doc.xpath('//EntityDescriptor/SPSSODescriptor')
        if len(spsso) > 1:
            logger.error('Only one SPSSODescriptor element must be present')

        for attr in ('protocolSupportEnumeration', 'AuthnRequestsSigned'):
            if attr not in spsso[0].attrib:
                logger.error(f'The {attr} attribute must be present - TR pag. 20')
                continue

            va = spsso[0].get(attr)
            if not va:
                logger.error(f'The {attr} attribute must have a value - TR pag. 20')
                continue
                
            if attr == 'AuthnRequestsSigned' and va.lower() != 'true':
                logger.error('The {attr} attribute must be true - TR pag. 20')


    def test_xmldsig(self):
        '''Verify the SP metadata signature'''
        tmp_file = NamedTemporaryFile()
        tmp_file.write(self.metadata)
        tmp_file.seek(0)
        
        xmlsec_cmd = ['xmlsec1',
                      '--verify',
                      '--insecure',
                      '--id-attr:ID',
                      'urn:oasis:names:tc:SAML:2.0:metadata:'
                      'EntityDescriptor',
                      tmp_file.name]
        cmd = ' '.join(xmlsec_cmd)
        is_valid = True
        msg = 'the metadata signature must be valid - TR pag. 19'
        try:
            subprocess.run(cmd, shell=True, check=True, 
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as err:
            is_valid = False
            lines = [msg]
            if err.stderr:
                stderr = (
                    'stderr: ' +
                    '\nstderr: '.join(
                        list(
                            filter(
                                None,
                                err.stderr.decode('utf-8').split('\n')
                            )
                        )
                    )
                )
                lines.append(stderr)
            if err.stdout:
                stdout = (
                    'stdout: ' +
                    '\nstdout: '.join(
                        list(
                            filter(
                                None,
                                err.stdout.decode('utf-8').split('\n')
                            )
                        )
                    )
                )
                lines.append(stdout)
            msg = '\n'.join(lines)        
            logger.error(msg)
            return

        xmlsec_cmd_string = ' '.join(xmlsec_cmd)
        logger.info(f'Metadata signature `{xmlsec_cmd_string}` -> OK')


    def test_metadata(self):
        self.xsd_check()
        
        # loop for all the attrs that starts with test_ ...
        self.test_EntityDescriptor()
        self.test_SPSSODescriptor()
        self.test_xmldsig()
