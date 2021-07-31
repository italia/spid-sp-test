import urllib


class SpidSpMetadataCheckAG(object):
    def test_extensions_public_ag(
        self,
        ext_types=[
            "//ContactPerson/Extensions/PublicServicesFullAggregator",
            "//ContactPerson/Extensions/PublicServicesLightAggregator",
            "//ContactPerson/Extensions/PrivateServicesFullAggregator",
            "//ContactPerson/Extensions/PrivateServicesLightAggregator",
            "//ContactPerson/Extensions/PublicServicesFullOperator",
            "//ContactPerson/Extensions/PublicServicesLightOperator",
        ],
        must=False,
    ):
        _method = f"{self.__class__.__name__}.test_extensions_public_ag"
        _data = dict(
            test_id="",
            references=[],
            method=_method,
        )
        for ext_type in ext_types:
            ctype = self.doc.xpath(ext_type)
            if must:
                self._assertTrue(
                    ctype, f"The {ext_type} element MUST be present", **_data
                )

            if ctype:
                self._assertFalse(
                    ctype[0].text,
                    f"The {ext_type.title()} element MUST be empty",
                    **_data,
                )

        return self.is_ok(_method)

    def test_entityid_qs(self):
        """The entityID MUST not contain the query-string part"""
        _method = f"{self.__class__.__name__}.test_entityid_qs"
        _data = dict(
            test_id="",
            references=[],
            method=_method,
        )
        entity_desc = self.doc.xpath("//EntityDescriptor")
        eid = entity_desc[0].get("entityID")

        qs = urllib.parse.splitquery(eid)

        self._assertFalse(
            qs[1],
            ("The entityID MUST not contain the query-string part"),
            description=eid,
            **_data,
        )
        return self.is_ok(_method)

    def test_entityid_contains(self, value=""):
        """The entityID MUST contain ..."""
        _method = f"{self.__class__.__name__}.test_entityid_contains"
        _data = dict(
            test_id="",
            references=[],
            method=_method,
        )
        entity_desc = self.doc.xpath("//EntityDescriptor")
        eid = entity_desc[0].get("entityID")
        self._assertTrue(
            value in eid,
            (f"The entityID MUST contain {value}"),
            description=eid,
            **_data,
        )
        return self.is_ok(_method)
