import urllib

from lxml import etree

from . indicepa import get_indicepa_by_ipacode


class SpidSpMetadataCheckAG(object):

    def test_extensions_public_ag(self, ext_types=[
                    "//ContactPerson/Extensions/PublicServicesFullAggregator",
                    "//ContactPerson/Extensions/PublicServicesLightAggregator",
                    "//ContactPerson/Extensions/PrivateServicesFullAggregator",
                    "//ContactPerson/Extensions/PrivateServicesLightAggregator",
                    "//ContactPerson/Extensions/PublicServicesFullOperator",
                    "//ContactPerson/Extensions/PublicServicesLightOperator"],
                    must=False):

        for ext_type in ext_types:
            ctype = self.doc.xpath(ext_type)
            if must:
                self._assertTrue(
                    ctype,
                    f'The {ext_type} element MUST be present',
                )

            if ctype:
                self._assertFalse(
                    ctype[0].text,
                    f'The {ext_type.title()} element MUST be empty',
                )

        return self.is_ok(f'{self.__class__.__name__}.test_extensions_public_ag')

    def test_entityid_qs(self):
        """ The entityID MUST not contains the query-string part """

        entity_desc = self.doc.xpath('//EntityDescriptor')
        eid = entity_desc[0].get('entityID')

        qs = urllib.parse.splitquery(eid)

        self._assertFalse(
            qs,
            (f'The entityID MUST not contains the query-string part'),
             description = eid,
        )
        return self.is_ok(f'{self.__class__.__name__}.test_entityid_qs')

    def test_entityid_contains(self, value=''):
        """ The entityID MUST contain ... """

        entity_desc = self.doc.xpath('//EntityDescriptor')
        eid = entity_desc[0].get('entityID')
        self._assertTrue(
            value in eid,
            (f'The entityID MUST contain {value}'),
             description = eid,
        )
        return self.is_ok(f'{self.__class__.__name__}.test_entityid_contains')
