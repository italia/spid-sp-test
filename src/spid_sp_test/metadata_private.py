class SpidSpMetadataCheckPrivate(object):
    def test_Contacts_Priv(self):
        self.doc.xpath("//ContactPerson")

        ipacode = self.doc.xpath("//ContactPerson/Extensions/IPACode")
        self._assertFalse(
            ipacode,
            "The IPACode element MUST NOT be present",
            description=ipacode,
        )

        exts = self.doc.xpath("//ContactPerson/Extensions/CessionarioCommittente")
        self._assertTrue(
            (len(exts) == 1),
            ("The CessionarioCommittente element MUST be present"),
            description=exts,
        )

        if exts:
            exts[0]
            tise = self.doc.xpath(
                "//ContactPerson/Extensions/CessionarioCommittente/TerzoIntermediarioSoggettoEmittente"
            )
            if tise:
                tise = tise[0]
                self._assertTrue(
                    tise.text,
                    "If the TerzoIntermediarioSoggettoEmittente element if present it MUST have a value",
                    description=tise,
                )

        return self.is_ok(f"{self.__class__.__name__}.test_Contacts_Priv")
