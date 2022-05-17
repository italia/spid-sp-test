import urllib

from .constants import XML_NAMESPACES, SPID_PROFILES
from .metadata_public import compose_contact_type_entity_type


class SpidSpMetadataCheckAG(object):
    def test_extensions_type(
        self,
        ext_types=SPID_PROFILES,
        contact_type: str = "other",
        entity_type: str = None,
    ):
        _method = f"{self.__class__.__name__}.test_extensions_type"
        _data = dict(
            references=[],
            method=_method,
        )

        xpatt = compose_contact_type_entity_type(contact_type, entity_type)

        for ext_type in SPID_PROFILES:
            ext = f"{xpatt}/Extensions/{ext_type}"
            ctype = self.doc.xpath(ext, namespaces=XML_NAMESPACES)

            if ext_type in ext_types:
                self._assertTrue(
                    ctype,
                    f"The {ext} element MUST be present",
                    test_id=[
                        "01.19.07-12",
                        "01.21.05",
                        "01.21.06",
                        "01.21.09",
                        "01.12.02",
                        "01.12.05",
                    ],
                    **_data,
                )
            else:
                self._assertFalse(
                    ctype,
                    f"The {ext} element MUST not be present",
                    test_id=[
                        "01.19.07-12",
                        "01.21.05",
                        "01.21.06",
                        "01.21.09",
                        "01.12.02",
                        "01.12.05",
                    ],
                    **_data,
                )

            if ctype:
                self._assertFalse(
                    ctype[0].text,
                    f"The {ext} element MUST be empty",
                    test_id=[
                        "01.12.03",
                        "01.12.06",
                        "01.19.00-05",
                        "01.21.01",
                        "01.21.02",
                        "01.21.03",
                    ],
                    **_data,
                )

        return self.is_ok(_method)

    def test_entityid_qs(self):
        """The entityID MUST not contain the query-string part"""
        _method = f"{self.__class__.__name__}.test_entityid_qs"
        _data = dict(
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
            test_id=["01.16.02"],
            **_data,
        )
        return self.is_ok(_method)

    def test_entityid_contains(self, value=""):
        """The entityID MUST contain ..."""
        _method = f"{self.__class__.__name__}.test_entityid_contains"
        _data = dict(
            references=[],
            method=_method,
        )
        entity_desc = self.doc.xpath("//EntityDescriptor")
        eid = entity_desc[0].get("entityID")
        self._assertTrue(
            value in eid,
            (f"The entityID MUST contain {value}"),
            description=eid,
            test_id=["01.16.03-10"],
            **_data,
        )
        return self.is_ok(_method)
