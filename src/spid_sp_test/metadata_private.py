class SpidSpMetadataCheckPrivate(object):
    def test_Contacts_Priv(self):
        self.doc.xpath("//ContactPerson")
        _method = f"{self.__class__.__name__}.test_Contacts_Priv"
        _data = dict(
            test_id = "",
            references = [],
            method = _method,
        )

        ipacode = self.doc.xpath("//ContactPerson/Extensions/IPACode")
        self._assertFalse(
            ipacode,
            "The IPACode element MUST NOT be present",
            description=ipacode, **_data
        )

        exts = self.doc.xpath("//ContactPerson/Extensions/CessionarioCommittente")
        self._assertTrue(
            (len(exts) == 1),
            ("The CessionarioCommittente element MUST be present"),
            description=exts, **_data
        )

        if exts:
            exts[0]
            tise = self.doc.xpath(
                "//ContactPerson/Extensions/CessionarioCommittente/TerzoIntermediarioSoggettoEmittente",
                **_data
            )
            if tise:
                tise = tise[0]
                self._assertTrue(
                    tise.text,
                    "If the TerzoIntermediarioSoggettoEmittente element if present it MUST have a value",
                    description=tise, **_data
                )

        return self.is_ok(_method)
