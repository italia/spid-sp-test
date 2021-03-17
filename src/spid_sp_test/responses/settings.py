from spid_sp_test.idp.settings import SAML2_IDP_CONFIG

NameIDNameQualifier = SAML2_IDP_CONFIG['entityid']

ATTRIBUTES_TYPES = {
    "dateOfBirth": "date",
    "expirationDate": "date"
}

ATTRIBUTES = {
    "spidCode": "AGID-001",
    "name": "SpidValidator",
    "familyName": "AgID",
    "placeOfBirth": "Roma",
    "countyOfBirth": "RM",
    "dateOfBirth": "2000-01-01",
    "gender": "M",
    "companyName": "Agenzia per l'Italia Digitale",
    "registeredOffice": "Via Listz 21 00144 Roma",
    "fiscalNumber": "TINIT-GDASDV00A01H501J",
    "ivaCode": "VATIT-97735020584",
    "idCard": "CartaIdentità AA00000000 ComuneRoma 2018-01-01 2028-01-01",
    "expirationDate": "2028-01-01",
    "mobilePhone": "+393331234567",
    "email": "spid.tech@agid.gov.it",
    "address": "Via Listz 21 00144 Roma",
    "digitalAddress": "pec@pecagid.gov.it",
    "companyFiscalNumber": "TINIT-GDASDV00A01H501J",
    "domicileStreetAddress": "Via Listz 21",
    "domicilePostalCode": "00144",
    "domicileMunicipality": "Roma",
    "domicileProvince": "RM",
    "domicileNation": "IT"
}


DEFAULT_RESPONSE = {
    "IssueInstant": "",              # "2021-03-04T15:48:46Z"
    "Issuer": SAML2_IDP_CONFIG['entityid'],
    "AssertionID": "",               # random, eg: _b8e3193c-aa49-4c45-8ca5-1c74d7de11b2
    "NameIDNameQualifier": NameIDNameQualifier,
    "NameID": "",                    # random, eg: _3fc08efa-a851-4855-9f03-9b881df8ca06
    "NotOnOrAfter": "",              # 2021-03-04T15:53:37Z
    "NotBefore": "",                 # 2021-03-04T15:48:46Z -> IssueInstant
    "AuthnIstant": "",               # 2021-03-04T15:48:46Z ~ IssueInstant
    "SessionIndex": "",              # _ffa3114b-f589-417b-8602-4b0275f6bafc
    "AuthnContextClassRef": "",      # https://www.spid.gov.it/SpidL1
    "Attributes": ATTRIBUTES
}


ATTRIBUTE_TMPL = """
    <saml:Attribute Name="{{ name }}">
    <saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema"
                         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                         xsi:type="xs:{{ type }}"
                         >{{ value }}</saml:AttributeValue>
    </saml:Attribute>
"""

SIGNATURE_TMPL = """
    <ds:Signature>
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
            <ds:Reference URI="{{ReferenceURI}}">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
                    <ds:DigestValue />
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue />
    </ds:Signature>
"""



RESPONSE_TESTS = {
    "1": {
        "name": "01. Response corretta",
        "description": "Response corretta. Risultato atteso: Ok",
        "status_codes": [200],
        "path": "base.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "2": {
        "name": "02. Response non firmata",
        "description": "Response non firmata. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "base.xml",
        "response": {},
        "sign_response": False,
        "sign_assertion": False
    },
    "3": {
        "name": "03. Response - Assertion non firmata",
        "description": "Response firmata, Assertion non firmata. (L'assertion deve essere sempre firmata, la response può essere firmata). Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "base.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": False
    },
    "4": {
        "name": "04. Response - Firma non valida",
        "description": "Response firmata con certificato diverso da quello registrato su SP. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "base.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True,
        "sign_credentials": {
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "certificate": "MIIDljCCAn6gAwIBAgIJAMSLv+GOwGWAMA0GCSqGSIb3DQEBCwUAMGAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTENMAsGA1UEBwwEUm9tZTENMAsGA1UECgwEQWdJRDENMAsGA1UECwwEQWdJRDEUMBIGA1UEAwwLYWdpZC5nb3YuaXQwHhcNMTkwNDA4MTc1MTMwWhcNMjAwNDA3MTc1MTMwWjBgMQswCQYDVQQGEwJJVDEOMAwGA1UECAwFSXRhbHkxDTALBgNVBAcMBFJvbWUxDTALBgNVBAoMBEFnSUQxDTALBgNVBAsMBEFnSUQxFDASBgNVBAMMC2FnaWQuZ292Lml0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsswE3L6ZbMWALv5fw73NmdZB5es3QaLNd3hq8sVVndDZUnM7yMHkYwPmlh1rFj82jPr2L9nasi32v6i283dsGCUxRH3VQo2Fi4awqvzx9g3mnd2p+CJKqN/xQuFyXkmDy7wKIopkv9EKJSFyyn9Y2h5FiKYucQoqQ2KJItt2y6tcTbhBRa7fMx99UPt1y5np31+oR4/BYWqLBtApMfGaXXDRNw/DBzmeew/uwC7tARMMG51MRBCZ83Mr5fIGeQZaYmDNCi+mIultLCVAZLqlv5h8p9bTAHNkNRpCh/V/I+q/L7Ajxfe/HEbydhJRyUjA0pmC4pAfvMlyDtQXMhh3FQIDAQABo1MwUTAdBgNVHQ4EFgQUodPRXj6pRrDfV011IiDnEOqnoMEwHwYDVR0jBBgwFoAUodPRXj6pRrDfV011IiDnEOqnoMEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEABkraIDMLDmpATNjR0uIu01gUOfIJMLWi75Ec03JGE/ljj2Kap7FO/RgqT5pmIUorb65rPlwsiP6Bv5Q7crDQMzVJdZwPzbboGlZR/dcqmQThgY4aOp7xcrmUCm3tWgwP52nw3QpLdVoiufy+5+MSuig6dklRqvx0tLGWgG2daUbdRtpEl8KtERMbVjoZGUqQE+WpIoKqxz2R84YY024XlMhRvxRAabFpYCNg5fAw0kRRXj3Zxmg7AdLzMStXHA/bked4ZoX6uJ19qLTOCLhlufQu8m3FL5Go5VL+qDdrNg7XYLxT1I5h1wtfebCA/e1IzHZmcUcAGVex4HgaAQwTNA==",
            "privateKey": "MIIEpAIBAAKCAQEAsswE3L6ZbMWALv5fw73NmdZB5es3QaLNd3hq8sVVndDZUnM7yMHkYwPmlh1rFj82jPr2L9nasi32v6i283dsGCUxRH3VQo2Fi4awqvzx9g3mnd2p+CJKqN/xQuFyXkmDy7wKIopkv9EKJSFyyn9Y2h5FiKYucQoqQ2KJItt2y6tcTbhBRa7fMx99UPt1y5np31+oR4/BYWqLBtApMfGaXXDRNw/DBzmeew/uwC7tARMMG51MRBCZ83Mr5fIGeQZaYmDNCi+mIultLCVAZLqlv5h8p9bTAHNkNRpCh/V/I+q/L7Ajxfe/HEbydhJRyUjA0pmC4pAfvMlyDtQXMhh3FQIDAQABAoIBACi5PVZF904GAfcyKv+7aGvkmCfVFkXV3fSbMcjP13tViVo1MuW7+9ftmISSeMSda0BbHN2zQhOZUn0+4US865roRbty6bL55vPrnqujZz0C14cXaNJChTzHnPz9un3tQp6R2sEZQm9KHoRshOfIb6VmhbHlH+jRRuUIOXH+CKXEpTPDU4Th+fdoYEOQY7NFHoobPrQ8IegYgODrWX2pTYf9AA5RitBP0Ju4lePgJX000T7WRpkSkAgi6arWzHzf5YUyAIATIVvm0RkuLIn9Q6YDQJa3lEmhEub4LZA6EpnqJYEjmfcOp5rPEKtq8tPWyuKvlT6bzHdtXz5zSG5Bo9UCgYEA6T8UAgcgRRJDYhKhsuhzwk3qahi0XqBJJp+XO8fdQXEh783P6pv5uYR1QUdDtgFOP05NEGz0Mzkyx5qxqlOr0yXlj0Tajb64S+5jyo8dqB2zxj0M8NLCxbQMvFN88tAHCJMPZeKOyq83XgWff2GzXqbQ9yh+5jauejW7z7zDEjsCgYEAxD0pLEFuBPeS1Fzz0P2UmsvKDbViqd9BlVwNwOR3YtSzT5hihUt1qVK22EVqlSWzF+QmAK76FQMoXiiQ22fNxTcaviNj2qZ9xhadS6RuF2MbxXVVQzXY4Oie/+mZg37fP0JZCQdlwOYp4UN4ZDf7NWJC5WJph4kx9Hj1liJGNu8CgYEAiOhhkh8kreZebv6Isz8GU5LweX4uwSxMQ8OBPbG/CV6ikOO5mvgayO4a9UojUH3LtBT93xpU7IwyZj9C8btTLAkeic3ciz7bZpZzNL50pe1pTH8hTWoosWtR3mkS+mNo/Xt0mlU1g3r9gM7EJDzw0CoSlkDK285U857+sp0V02kCgYBpCnPnhH5nmj21/qtjytioozzcaaMOWrq4QDX8ck6VUFVK3b6equ2oXOYSjdWnUC61MyJEa2ThqncJL52aU84JKp3d+QOSHlxkk+ZOfw2O5zYOU+f3ufMFMH8rbNcHU/ob2l/ePV9yCcGRGpRu0KhewuIb9rmWGxHqUnTikCYVcQKBgQDUWuS6hNq5qUSCIGL5e8CMmc/wSAvQFgxZV4VgJdPexykaJc4LKoFYqbRSyOSJ2vpxxWa6qIPU0+kgNZT7lBf8JOd4MIg5sg6Q8hIQk/I6cTM3F3ehpsKoq9K7IcJQQWqHgkONEFeghIZH0nzhnwrtVuFZiCzc7c671MmJMhnPZQ=="
        }
    },
    # test 8 e 9 manca ID per firmare con xmlsec1
    # "8": {
        # "name": "08. Response - ID non specificato",
        # "description": "Attributo ID non specificato. Risultato atteso: KO",
        # "status_codes": [403, 500],
        # "path": "case-08.xml",
        # "response": {
            # "ResponseID": ""
        # },
        # "sign_response": True,
        # "sign_assertion": True
    # },
    # "9": {
        # "name": "09. Response - ID mancante",
        # "description": "Attributo ID mancante. Risultato atteso: KO",
        # "status_codes": [403, 500],
        # "path": "case-09.xml",
        # "response": {},
        # "sign_response": True,
        # "sign_assertion": True
    # },
    "10": {
        "name": "10. Response - Version diverso da 2.0",
        "description": "Attributo Version diverso da 2.0. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-10.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "11": {
        "name": "11. Response - IssueInstant non specificato",
        "description": "Attributo IssueInstant non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-11.xml",
        "response": {
            "IssueInstant": "",
        },
        "sign_response": True,
        "sign_assertion": True
    },
    "12": {
        "name": "12. Response - IssueInstant mancante",
        "description": "Attributo IssueInstant mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-12.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "13": {
        "name": "13. Response - Formato IssueInstant non corretto",
        "description": "Attributo IssueInstant avente formato non corretto. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-13.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "14": {
        "name": "14. Response - IssueInstant precedente Request",
        "description": "Attributo IssueInstant precedente a IssueInstant della request. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "base.xml",
        "response": {
            "IssueInstant": "2018-01-01T00:00:00Z",
        },
        "sign_response": True,
        "sign_assertion": True
    },
    "15": {
        "name": "15. Response - IssueInstant successivo Request",
        "description": "Attributo IssueInstant successivo all'istante di ricezione. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "base.xml",
        "response": {
            "IssueInstant": "2099-01-01T00:00:00Z",
        },
        "sign_response": True,
        "sign_assertion": True
    },
    "16": {
        "name": "16. Response - InResponseTo non specificato",
        "description": "Attributo InResponseTo non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-16.xml",
        "response": {
            "InResponseTo": ""
        },
        "sign_response": True,
        "sign_assertion": True
    },
    "17": {
        "name": "17. Response - InResponseTo mancante",
        "description": "Attributo InResponseTo mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-17.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "18": {
        "name": "18. Response - InResponseTo diverso da Request",
        "description": "Attributo InResponseTo diverso da ID request. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "base.xml",
        "response": {
            "AuthnRequestID": "inresponsetodiversodaidrequest",
        },
        "sign_response": True,
        "sign_assertion": True
    },
    "19": {
        "name": "19. Response - Destination non specificato",
        "description": "Attributo Destination non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-19.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "20": {
        "name": "20. Response - Destination mancante",
        "description": "Attributo Destination mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-20.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "21": {
        "name": "21. Response - Destination diverso da AssertionConsumerServiceURL",
        "description": "Attributo Destination diverso da AssertionConsumerServiceURL. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-21.xml",
        "response": {
            "AssertionConsumerURL": "diversodaassertionconsumerserviceurl"
        },
        "sign_response": True,
        "sign_assertion": True
    },
    "22": {
        "name": "22. Response - Elemento Status non specificato",
        "description": "Elemento Status non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-22.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "23": {
        "name": "23. Response - Elemento Status mancante",
        "description": "Elemento Status mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-23.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "24": {
        "name": "24. Response - Elemento StatusCode non specificato",
        "description": "Elemento StatusCode non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-24.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    # identico al 22
    # "25": {
        # "name": "25. Response - Elemento StatusCode mancante",
        # "description": "Elemento StatusCode mancante. Risultato atteso: KO",
        # "status_codes": [403, 500],
        # "path": "case-25.xml",
        # "response": {},
        # "sign_response": True,
        # "sign_assertion": True
    # },
    "26": {
        "name": "26. Response - Elemento StatusCode diverso da success (non valido)",
        "description": "Elemento StatusCode diverso da Success (non valido). Risultato atteso: KO. il S.P. deve mostrare schermata di errore",
        "status_codes": [403, 500],
        "path": "case-26.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "27": {
        "name": "27. Response - Elemento Issuer non specificato",
        "description": "Elemento Issuer non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-27.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "28": {
        "name": "28. Response - Elemento Issuer mancante",
        "description": "Elemento Issuer mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-28.xml",
        "response": {},
        "sign_response": False,
        "sign_assertion": True
    },
    "29": {
        "name": "29. Response - Elemento Assertion Issuer diverso da EntityID IdP",
        "description": "Elemento Issuer diverso da EntityID IdP. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-29.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "30": {
        "name": "30. Response - Attributo Format di Issuer diverso",
        "description": "L'attributo Format di Issuer deve essere omesso o assumere valore urn:oasis:names:tc:SAML:2.0:nameid-format:entity. In questo test il valore è diverso. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-30.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "31": {
        "name": "31. Response - Attributo Format di Issuer omesso",
        "description": "L'attributo Format di Issuer deve essere omesso o assumere valore urn:oasis:names:tc:SAML:2.0:nameid-format:entity. In questo test il valore è omesso. Risultato atteso: Ok",
        "status_codes": [200],
        "path": "case-31.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "32": {
        "name": "32. Response - Elemento Assertion mancante",
        "description": "Elemento Assertion mancante ed esito positivo autenticazione. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-32.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": False
    },
    # manca ID per firmare con xmlsec1
    # "33": {
        # "name": "33. Assertion - Attributo ID non specificato",
        # "description": "Attributo ID dell'Assertion non specificato. Risultato atteso: KO",
        # "status_codes": [403, 500],
        # "path": "case-33.xml",
        # "response": {},
        # "sign_response": True,
        # "sign_assertion": True
    # },
    # "34": {
        # "name": "34. Assertion - Attributo ID mancante",
        # "description": "Attributo ID dell'Assertion mancante. Risultato atteso: KO",
        # "status_codes": [403, 500],
        # "path": "case-34.xml",
        # "response": {},
        # "sign_response": True,
        # "sign_assertion": True
    # },
    "35": {
        "name": "35. Assertion - Attributo Version diverso da 2.0",
        "description": "Attributo Version dell'Assertion diverso da 2.0. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-35.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "36": {
        "name": "36. Assertion - Attributo IssueInstant non specificato",
        "description": "Attributo IssueInstant dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-36.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "37": {
        "name": "37. Assertion - Attributo IssueInstant mancante",
        "description": "Attributo IssueInstant dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-37.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "38": {
        "name": "38. Assertion - Attributo IssueInstant avente formato non corretto",
        "description": "Attributo IssueInstant dell'Assertion avente formato non corretto. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-38.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "39": {
        "name": "39. Assertion - Attributo IssueInstant precedente a IssueInstant della Request",
        "description": "Attributo IssueInstant dell'Assertion precedente a IssueInstant della Request. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-39.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "40": {
        "name": "40. Assertion - Attributo IssueInstant successivo a IssueInstant della Request",
        "description": "Attributo IssueInstant dell'Assertion successivo a IssueInstant della Request. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-40.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "41": {
        "name": "41. Assertion - Elemento Subject non specificato",
        "description": "Elemento Subject dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-41.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "42": {
        "name": "42. Assertion - Elemento Subject mancante",
        "description": "Elemento Subject dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-42.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "43": {
        "name": "43. Assertion - Elemento NameID non specificato",
        "description": "Elemento NameID dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-43.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "44": {
        "name": "44. Assertion - Elemento NameID mancante",
        "description": "Elemento NameID dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-44.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "45": {
        "name": "45. Assertion - Attributo Format di NameID non specificato",
        "description": "Attributo Format dell'elemento NameID dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-45.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "46": {
        "name": "46. Assertion - Attributo Format di NameID mancante",
        "description": "Attributo Format dell'elemento NameID dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-46.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "47": {
        "name": "47. Assertion - Attributo Format di NameID diverso",
        "description": "Attributo Format di NameID dell'Assertion diverso da urn:oasis:names:tc:SAML:2.0:nameidformat:transient. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-47.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "48": {
        "name": "48. Assertion - Attributo NameQualifier di NameID non specificato",
        "description": "Attributo NameQualifier di NameID dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-48.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "49": {
        "name": "49. Assertion - Attributo NameQualifier di NameID mancante",
        "description": "Attributo NameQualifier di NameID dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-49.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "51": {
        "name": "51. Assertion - Elemento SubjectConfirmation non specificato",
        "description": "Elemento SubjectConfirmation dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-51.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "52": {
        "name": "52. Assertion - Elemento SubjectConfirmation mancante",
        "description": "Elemento SubjectConfirmation dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-52.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "53": {
        "name": "53. Assertion - Attributo Method di SubjectConfirmation non specificato",
        "description": "Attributo Method di SubjectConfirmation dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-53.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "54": {
        "name": "54. Assertion - Attributo Method di SubjectConfirmation mancante",
        "description": "Attributo Method di SubjectConfirmation dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-54.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "55": {
        "name": "55. Assertion - Attributo Method di SubjectConfirmation diverso",
        "description": "Attributo Method di SubjectConfirmation dell'Assertion diverso da urn:oasis:names:tc:SAML:2.0:cm:bearer. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-55.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "56": {
        "name": "56. Assertion - Elemento SubjectConfirmationData mancante",
        "description": "Elemento SubjectConfirmationData dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-56.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "57": {
        "name": "57. Assertion - Attributo Recipient di SubjectConfirmationData non specificato",
        "description": "Attributo Recipient di SubjectConfirmationData dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-57.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "58": {
        "name": "58. Assertion - Attributo Recipient di SubjectConfirmationData mancante",
        "description": "Attributo Recipient di SubjectConfirmationData dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-58.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "59": {
        "name": "59. Assertion - Attributo Recipient di SubjectConfirmationData diverso",
        "description": "Attributo Recipient di SubjectConfirmationData dell'Assertion diverso da AssertionConsumerServiceURL. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-59.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "60": {
        "name": "60. Assertion - Attributo InResponseTo di SubjectConfirmationData non specificato",
        "description": "Attributo InResponseTo di SubjectConfirmationData dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-60.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "61": {
        "name": "61. Assertion - Attributo InResponseTo di SubjectConfirmationData mancante",
        "description": "Attributo InResponseTo di SubjectConfirmationData dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-61.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "62": {
        "name": "62. Assertion - Attributo InResponseTo di SubjectConfirmationData diverso da ID request",
        "description": "Attributo InResponseTo di SubjectConfirmationData dell'Assertion diverso da ID request. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-62.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "63": {
        "name": "63. Assertion - Attributo NotOnOrAfter di SubjectConfirmationData non specificato",
        "description": "Attributo NotOnOrAfter di SubjectConfirmationData dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-63.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "64": {
        "name": "64. Assertion - Attributo NotOnOrAfter di SubjectConfirmationData mancante",
        "description": "Attributo NotOnOrAfter di SubjectConfirmationData mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-64.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "65": {
        "name": "65. Assertion - Attributo NotOnOrAfter di SubjectConfirmationData avente formato non corretto",
        "description": "Attributo NotOnOrAfter di SubjectConfirmationData avente formato non corretto. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-65.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "66": {
        "name": "66. Assertion - Attributo NotOnOrAfter di SubjectConfirmationData precedente all'istante di ricezione della response",
        "description": "Attributo NotOnOrAfter di SubjectConfirmationData precedente all'istante di ricezione della response. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-66.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    # identico al 29
    # "67": {
        # "name": "67. Assertion - Elemento Issuer non specificato",
        # "description": "Elemento Issuer dell'Assertion non specificato. Risultato atteso: KO",
        # "status_codes": [403, 500],
        # "path": "case-67.xml",
        # "response": {},
        # "sign_response": True,
        # "sign_assertion": True
    # },
    "68": {
        "name": "68. Assertion - Elemento Issuer mancante",
        "description": "Elemento Issuer dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-68.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "69": {
        "name": "69. Assertion - Elemento Issuer diverso da EntityID IdP",
        "description": "Elemento Issuer dell'Assertion diverso da EntityID IdP. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-69.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "70": {
        "name": "70. Assertion - Attributo Format di Issuer non specificato",
        "description": "Attributo Format di Issuer dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-70.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "71": {
        "name": "71. Assertion - Attributo Format di Issuer mancante",
        "description": "Attributo Format di Issuer dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-71.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "72": {
        "name": "72. Assertion - Attributo Format di Issuer diverso",
        "description": "L'attributo Format di Issuer dell'Assertion deve essere presente con il valore urn:oasis:names:tc:SAML:2.0:nameid-format:entity. In questo test, invece, il valore è diverso. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-72.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "73": {
        "name": "73. Assertion - Elemento Conditions non specificato",
        "description": "Elemento Conditions dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-73.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "74": {
        "name": "74. Assertion - Elemento Conditions mancante",
        "description": "Elemento Conditions dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-74.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "75": {
        "name": "75. Assertion - Attributo NotBefore di Condition non specificato",
        "description": "Attributo NotBefore di Condition dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-75.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "76": {
        "name": "76. Assertion - Attributo NotBefore di Condition mancante",
        "description": "Attributo NotBefore di Condition dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-76.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "77": {
        "name": "77. Assertion - Attributo NotBefore di Condition avente formato non corretto",
        "description": "Attributo NotBefore di Condition dell'Assertion avente formato non corretto. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-77.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "78": {
        "name": "78. Assertion - Attributo NotBefore di Condition successivo all'instante di ricezione della response",
        "description": "Attributo NotBefore di Condition dell'Assertion successivo all'instante di ricezione della response. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-78.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "79": {
        "name": "79. Assertion - Attributo NotOnOrAfter di Condition non specificato",
        "description": "Attributo NotOnOrAfter di Condition dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-79.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "80": {
        "name": "80. Assertion - Attributo NotOnOrAfter di Condition mancante",
        "description": "Attributo NotOnOrAfter di Condition dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-80.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "81": {
        "name": "81. Assertion - Attributo NotOnOrAfter di Condition avente formato non corretto",
        "description": "Attributo NotOnOrAfter di Condition dell'Assertion avente formato non corretto. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-81.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "82": {
        "name": "82. Assertion - Attributo NotOnOrAfter di Condition precedente all'istante di ricezione della response",
        "description": "Attributo NotOnOrAfter di Condition dell'Assertion precedente all'istante di ricezione della response. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-82.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "83": {
        "name": "83. Assertion - Elemento AudienceRestriction di Condition non specificato",
        "description": "Elemento AudienceRestriction di Condition dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-83.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    # identico al 73
    # "84": {
        # "name": "84. Assertion - Elemento AudienceRestriction di Condition mancante",
        # "description": "Elemento AudienceRestriction di Condition dell'Assertion mancante. Risultato atteso: KO",
        # "status_codes": [403, 500],
        # "path": "case-84.xml",
        # "response": {},
        # "sign_response": True,
        # "sign_assertion": True
    # },
    "85": {
        "name": "85. Assertion - Elemento Audience di AudienceRestriction di Condition non specificato",
        "description": "Elemento Audience di AudienceRestriction di Condition dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-85.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "86": {
        "name": "86. Assertion - Elemento Audience di AudienceRestriction di Condition mancante",
        "description": "Elemento Audience di AudienceRestriction di Condition dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-86.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "87": {
        "name": "87. Assertion - Elemento Audience di AudienceRestriction di Condition diverso da Entity Id del Service Provider",
        "description": "Elemento Audience di AudienceRestriction di Condition dell'Assertion diverso da Entity Id del Service Provider. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-87.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "88": {
        "name": "88. Assertion - Elemento AuthStatement non specificato",
        "description": "Elemento AuthStatement dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-88.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "89": {
        "name": "89. Assertion - Elemento AuthStatement mancante",
        "description": "Elemento AuthStatement dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-89.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "90": {
        "name": "90. Assertion - Elemento AuthnContext di AuthStatement non specificato",
        "description": "Elemento AuthnContext di AuthStatement dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-90.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    # identico a 88
    # "91": {
        # "name": "91. Assertion - Elemento AuthnContext di AuthStatement mancante",
        # "description": "Elemento AuthnContext di AuthStatement dell'Assertion mancante. Risultato atteso: KO",
        # "status_codes": [403, 500],
        # "path": "case-91.xml",
        # "response": {},
        # "sign_response": True,
        # "sign_assertion": True
    # },
    "92": {
        "name": "92. Assertion - Elemento AuthContextClassRef di AuthnContext di AuthStatement non specificato",
        "description": "Elemento AuthContextClassRef di AuthnContext di AuthStatement dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-92.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "93": {
        "name": "93. Assertion - Elemento AuthContextClassRef di AuthnContext di AuthStatement mancante",
        "description": "Elemento AuthContextClassRef di AuthnContext di AuthStatement dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-93.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "94": {
        "name": "94. Assertion - Elemento AuthContextClassRef impostato su https://www.spid.gov.it/SpidL1",
        "description": "Elemento AuthContextClassRef impostato su https://www.spid.gov.it/SpidL1. Risultato atteso: fare attenzione al livello richiesto sulla request.",
        "path": "base.xml",
        "response": {

            "AuthnContextClassRef": "https://www.spid.gov.it/SpidL1",
            "Attributes": ATTRIBUTES
        },
        "sign_response": True,
        "sign_assertion": True
    },
    "95": {
        "name": "95. Assertion - Elemento AuthContextClassRef impostato su https://www.spid.gov.it/SpidL2",
        "description": "Elemento AuthContextClassRef impostato su https://www.spid.gov.it/SpidL2. Risultato atteso: fare attenzione al livello richiesto sulla request.",
        "path": "base.xml",
        "response": {
            "AuthnContextClassRef": "https://www.spid.gov.it/SpidL2",
        },
        "sign_response": True,
        "sign_assertion": True
    },
    "96": {
        "name": "96. Assertion - Elemento AuthContextClassRef impostato su https://www.spid.gov.it/SpidL3",
        "description": "Elemento AuthContextClassRef impostato su https://www.spid.gov.it/SpidL3. Risultato atteso: fare attenzione al livello richiesto sulla request.",
        "path": "base.xml",
        "response": {
            "AuthnContextClassRef": "https://www.spid.gov.it/SpidL3",
        },
        "sign_response": True,
        "sign_assertion": True
    },
    "97": {
        "name": "97. Assertion - Elemento AuthContextClassRef impostato ad un valore non previsto",
        "description": "Elemento AuthContextClassRef impostato ad un valore non previsto. Es. specifica precedente. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "base.xml",
        "response": {
            "AuthnContextClassRef": "urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL1",
        },
        "sign_response": True,
        "sign_assertion": True
    },
    "98": {
        "name": "98. Assertion - Elemento AttributeStatement presente, ma sottoelemento Attribute mancante ",
        "description": "Elemento AttributeStatement presente, ma sottoelemento Attribute mancante. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-98.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "99": {
        "name": "99. Assertion - Elemento AttributeStatement presente, con sottoelemento Attribute non specificato",
        "description": "Elemento AttributeStatement presente, ma sottoelemento Attribute non specificato. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "case-99.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True
    },
    "100": {
        "name": "100. Assertion - Firma diversa",
        "description": "Assertion firmata con certificato diverso. Risultato atteso: KO",
        "status_codes": [403, 500],
        "path": "base.xml",
        "response": {},
        "sign_response": True,
        "sign_assertion": True,
        "sign_credentials": {
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "certificate": "MIIDljCCAn6gAwIBAgIJAMSLv+GOwGWAMA0GCSqGSIb3DQEBCwUAMGAxCzAJBgNVBAYTAklUMQ4wDAYDVQQIDAVJdGFseTENMAsGA1UEBwwEUm9tZTENMAsGA1UECgwEQWdJRDENMAsGA1UECwwEQWdJRDEUMBIGA1UEAwwLYWdpZC5nb3YuaXQwHhcNMTkwNDA4MTc1MTMwWhcNMjAwNDA3MTc1MTMwWjBgMQswCQYDVQQGEwJJVDEOMAwGA1UECAwFSXRhbHkxDTALBgNVBAcMBFJvbWUxDTALBgNVBAoMBEFnSUQxDTALBgNVBAsMBEFnSUQxFDASBgNVBAMMC2FnaWQuZ292Lml0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsswE3L6ZbMWALv5fw73NmdZB5es3QaLNd3hq8sVVndDZUnM7yMHkYwPmlh1rFj82jPr2L9nasi32v6i283dsGCUxRH3VQo2Fi4awqvzx9g3mnd2p+CJKqN/xQuFyXkmDy7wKIopkv9EKJSFyyn9Y2h5FiKYucQoqQ2KJItt2y6tcTbhBRa7fMx99UPt1y5np31+oR4/BYWqLBtApMfGaXXDRNw/DBzmeew/uwC7tARMMG51MRBCZ83Mr5fIGeQZaYmDNCi+mIultLCVAZLqlv5h8p9bTAHNkNRpCh/V/I+q/L7Ajxfe/HEbydhJRyUjA0pmC4pAfvMlyDtQXMhh3FQIDAQABo1MwUTAdBgNVHQ4EFgQUodPRXj6pRrDfV011IiDnEOqnoMEwHwYDVR0jBBgwFoAUodPRXj6pRrDfV011IiDnEOqnoMEwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEABkraIDMLDmpATNjR0uIu01gUOfIJMLWi75Ec03JGE/ljj2Kap7FO/RgqT5pmIUorb65rPlwsiP6Bv5Q7crDQMzVJdZwPzbboGlZR/dcqmQThgY4aOp7xcrmUCm3tWgwP52nw3QpLdVoiufy+5+MSuig6dklRqvx0tLGWgG2daUbdRtpEl8KtERMbVjoZGUqQE+WpIoKqxz2R84YY024XlMhRvxRAabFpYCNg5fAw0kRRXj3Zxmg7AdLzMStXHA/bked4ZoX6uJ19qLTOCLhlufQu8m3FL5Go5VL+qDdrNg7XYLxT1I5h1wtfebCA/e1IzHZmcUcAGVex4HgaAQwTNA==",
            "privateKey": "MIIEpAIBAAKCAQEAsswE3L6ZbMWALv5fw73NmdZB5es3QaLNd3hq8sVVndDZUnM7yMHkYwPmlh1rFj82jPr2L9nasi32v6i283dsGCUxRH3VQo2Fi4awqvzx9g3mnd2p+CJKqN/xQuFyXkmDy7wKIopkv9EKJSFyyn9Y2h5FiKYucQoqQ2KJItt2y6tcTbhBRa7fMx99UPt1y5np31+oR4/BYWqLBtApMfGaXXDRNw/DBzmeew/uwC7tARMMG51MRBCZ83Mr5fIGeQZaYmDNCi+mIultLCVAZLqlv5h8p9bTAHNkNRpCh/V/I+q/L7Ajxfe/HEbydhJRyUjA0pmC4pAfvMlyDtQXMhh3FQIDAQABAoIBACi5PVZF904GAfcyKv+7aGvkmCfVFkXV3fSbMcjP13tViVo1MuW7+9ftmISSeMSda0BbHN2zQhOZUn0+4US865roRbty6bL55vPrnqujZz0C14cXaNJChTzHnPz9un3tQp6R2sEZQm9KHoRshOfIb6VmhbHlH+jRRuUIOXH+CKXEpTPDU4Th+fdoYEOQY7NFHoobPrQ8IegYgODrWX2pTYf9AA5RitBP0Ju4lePgJX000T7WRpkSkAgi6arWzHzf5YUyAIATIVvm0RkuLIn9Q6YDQJa3lEmhEub4LZA6EpnqJYEjmfcOp5rPEKtq8tPWyuKvlT6bzHdtXz5zSG5Bo9UCgYEA6T8UAgcgRRJDYhKhsuhzwk3qahi0XqBJJp+XO8fdQXEh783P6pv5uYR1QUdDtgFOP05NEGz0Mzkyx5qxqlOr0yXlj0Tajb64S+5jyo8dqB2zxj0M8NLCxbQMvFN88tAHCJMPZeKOyq83XgWff2GzXqbQ9yh+5jauejW7z7zDEjsCgYEAxD0pLEFuBPeS1Fzz0P2UmsvKDbViqd9BlVwNwOR3YtSzT5hihUt1qVK22EVqlSWzF+QmAK76FQMoXiiQ22fNxTcaviNj2qZ9xhadS6RuF2MbxXVVQzXY4Oie/+mZg37fP0JZCQdlwOYp4UN4ZDf7NWJC5WJph4kx9Hj1liJGNu8CgYEAiOhhkh8kreZebv6Isz8GU5LweX4uwSxMQ8OBPbG/CV6ikOO5mvgayO4a9UojUH3LtBT93xpU7IwyZj9C8btTLAkeic3ciz7bZpZzNL50pe1pTH8hTWoosWtR3mkS+mNo/Xt0mlU1g3r9gM7EJDzw0CoSlkDK285U857+sp0V02kCgYBpCnPnhH5nmj21/qtjytioozzcaaMOWrq4QDX8ck6VUFVK3b6equ2oXOYSjdWnUC61MyJEa2ThqncJL52aU84JKp3d+QOSHlxkk+ZOfw2O5zYOU+f3ufMFMH8rbNcHU/ob2l/ePV9yCcGRGpRu0KhewuIb9rmWGxHqUnTikCYVcQKBgQDUWuS6hNq5qUSCIGL5e8CMmc/wSAvQFgxZV4VgJdPexykaJc4LKoFYqbRSyOSJ2vpxxWa6qIPU0+kgNZT7lBf8JOd4MIg5sg6Q8hIQk/I6cTM3F3ehpsKoq9K7IcJQQWqHgkONEFeghIZH0nzhnwrtVuFZiCzc7c671MmJMhnPZQ=="
        }
    },
    "103": {
        "name": "103. Assertion - Set di attributi inviato diverso da quello richiesto",
        "description": "Set di attributi inviato diverso da quello richiesto",
        "path": "base.xml",
        "response": {

            "Attributes": {
                "spidCode": "AGID-001",
                "address": "via Test"
            }
        },
        "sign_response": True,
        "sign_assertion": True
    },
    "104": {
        "name": "104. Anomalie utente - Ripetuta sottomissione di credenziali errate (Anomalia 19)",
        "description": "Elemento StatusCode ErrorCode nr19. Autenticazione fallita per ripetuta sottomissione di credenziali errate. Risultato atteso: KO. il S.P. deve mostrare schermata di errore",
        "status_codes": [403, 500],
        "path": "case-anomalie-utente.xml",
        "response": {
            "StatusCode": "urn:oasis:names:tc:SAML:2.0:status:Responder",
            "SubStatus": "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            "StatusMessage": "ErrorCode nr19"
        },
        "sign_response": True,
        "sign_assertion": False
    },
    "105": {
        "name": "105. Anomalie utente - Utente privo di credenziali compatibili (Anomalia 20)",
        "description": "Elemento StatusCode ErrorCode nr20. Utente privo di credenziali compatibili con il livello richiesto dal fornitore del servizio. Risultato atteso: KO. il S.P. deve mostrare schermata di errore",
        "status_codes": [403, 500],
        "path": "case-anomalie-utente.xml",
        "response": {
            "StatusCode": "urn:oasis:names:tc:SAML:2.0:status:Responder",
            "SubStatus": "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            "StatusMessage": "ErrorCode nr20"
        },
        "sign_response": True,
        "sign_assertion": False
    },
    "106": {
        "name": "106. Anomalie utente - Timeout (Anomalia 21)",
        "description": "Elemento StatusCode ErrorCode nr21. Timeout durante l'autenticazione utente. Risultato atteso: KO. il S.P. deve mostrare schermata di errore",
        "status_codes": [403, 500],
        "path": "case-anomalie-utente.xml",
        "response": {
            "StatusCode": "urn:oasis:names:tc:SAML:2.0:status:Responder",
            "SubStatus": "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            "StatusMessage": "ErrorCode nr21"
        },
        "sign_response": True,
        "sign_assertion": False
    },
    "107": {
        "name": "107. Anomalie utente - Consenso negato (Anomalia 22)",
        "description": "Elemento StatusCode ErrorCode nr22. Utente nega il consenso all'invio di dati al SP in caso di sessione vigente. Risultato atteso: KO. il S.P. deve mostrare schermata di errore",
        "status_codes": [403, 500],
        "path": "case-anomalie-utente.xml",
        "response": {
            "StatusCode": "urn:oasis:names:tc:SAML:2.0:status:Responder",
            "SubStatus": "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            "StatusMessage": "ErrorCode nr22"
        },
        "sign_response": True,
        "sign_assertion": False
    },
    "108": {
        "name": "108. Anomalie utente - Credenziali bloccate (Anomalia 23)",
        "description": "Elemento StatusCode ErrorCode nr23. Utente con identità sospesa/revocata o con credenziali bloccate. Risultato atteso: KO. il S.P. deve mostrare schermata di errore",
        "status_codes": [403, 500],
        "path": "case-anomalie-utente.xml",
        "response": {
            "StatusCode": "urn:oasis:names:tc:SAML:2.0:status:Responder",
            "SubStatus": "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            "StatusMessage": "ErrorCode nr23"
        },
        "sign_response": True,
        "sign_assertion": False
    },
    # ValueError: Unicode strings with encoding declaration are not supported. Please use bytes input or XML fragments without declaration.
    # "109": {
        # "name": "109. Attributi senza NameFormat",
        # "description": "Response corretta. Risultato atteso: Ok",
        # "status_codes": [200],
        # "path": "case-109.xml",
        # "response": {},
        # "attributesNameFormat": False,
        # "sign_response": True,
        # "sign_assertion": True
    # },

    # definire Millis
    # "110": {
        # "name": "110. Response - IssueInstant con millisecondi",
        # "description": "Attributo IssueInstant specificato con millisecondi. Risultato atteso: Ok",
        # "status_codes": [200],
        # "path": "case-110.xml",
        # "response": {},
        # "sign_response": True,
        # "sign_assertion": True
    # },
    "111": {
        "name": "111. Anomalie utente - Processo di autenticazione annullato dall'utente (Anomalia 25)",
        "description": "Elemento StatusCode ErrorCode nr25. Processo di autenticazione annullato dall'utente. Risultato atteso: KO. il S.P. deve mostrare schermata di errore",
        "status_codes": [403, 500],
        "path": "case-anomalie-utente.xml",
        "response": {
            "StatusCode": "urn:oasis:names:tc:SAML:2.0:status:Responder",
            "SubStatus": "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            "StatusMessage": "ErrorCode nr25"
        },
        "sign_response": True,
        "sign_assertion": False
    }
}


TEST_SUITE = {
    "test-suite-1": {
        "description": "Test Response",
        "response": {
            "AssertionConsumerURL": "",
            "ResponseID": "",
            "AuthnRequestID": ""
        },
        "cases": RESPONSE_TESTS
    },
    "test-logout": {
        "description": "Test Logout Response",
        "response": {
            "ResponseID": "",
            "IssueInstant": "",
            "Destination": "",
            "AuthnRequestID": "",
            "NameQualifier": NameIDNameQualifier,
            "Issuer": ""
        },
        "cases": {
            "1": {
                "name": "01. Logout",
                "description": "Logout corretto",
                "path": "logout-1.xml",
                "response": {},
                "sign_response": True
            }
        }
    }
}
