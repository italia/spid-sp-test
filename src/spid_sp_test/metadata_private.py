from . constants import XML_NAMESPACES
from . metadata_public import compose_contact_type_entity_type


class SpidSpMetadataCheckPrivate(object):

    def test_Contacts_Priv(self, contact_type:str="billing", entity_type:str=None):
        _method = f"{self.__class__.__name__}.test_Contacts_Priv"
        _data = dict(
            references=[],
            method=_method,
        )
        
        xpatt = compose_contact_type_entity_type(contact_type, entity_type)

        exts = self.doc.xpath(f"{xpatt}/Extensions/CessionarioCommittente", namespaces=XML_NAMESPACES)
        self._assertTrue(
            (len(exts) == 1),
            ("The CessionarioCommittente element MUST be present"),
            description=exts,
            test_id = ['1.14.4'], **_data,
        )

        if exts:
            exts[0]
            tise = self.doc.xpath(
                f"{xpatt}/Extensions/CessionarioCommittente/TerzoIntermediarioSoggettoEmittente",
                namespaces=XML_NAMESPACES
            )
            if tise:
                tise = tise[0]
                self._assertTrue(
                    tise.text,
                    "If the TerzoIntermediarioSoggettoEmittente element if present it MUST have a value",
                    description=tise,
                    **_data,
                )

        return self.is_ok(_method)

    def test_Contacts_Priv_VAT(self):
        _method = f"{self.__class__.__name__}.test_Contacts_Priv_VAT"
        _data = dict(
            references=[],
            method=_method,
        )

        ipacode = self.doc.xpath("//ContactPerson/Extensions/IPACode")
        self._assertFalse(
            ipacode,
            "The IPACode element MUST NOT be present",
            description=ipacode,
            test_id = ['1.12.0'], **_data,
        )
