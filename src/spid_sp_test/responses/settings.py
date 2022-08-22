from spid_sp_test.idp.settings import SAML2_IDP_CONFIG

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
NameIDNameQualifier = SAML2_IDP_CONFIG["entityid"]

ATTRIBUTES_TYPES = {"dateOfBirth": "date", "expirationDate": "date"}

HTTP_STATUS_ERROR_CODES = [400, 401, 403, 422, 500]

ATTRIBUTES = {
    "spidCode": "AGID-001",
    "name": "SpidValidator",
    "familyName": "AgID",
    "placeOfBirth": "Roma",
    "countyOfBirth": "RM",
    "dateOfBirth": "2000-01-01",
    "gender": "M",
    "companyName": "Agenzia per l'Italia Digitale",
    "companyFiscalNumber": "TINIT-MHASDV02A31H671H",
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
    "domicileNation": "IT",
}


DEFAULT_RESPONSE = {
    "IssueInstant": "",  # "2021-03-04T15:48:46Z"
    "Issuer": SAML2_IDP_CONFIG["entityid"],
    "AssertionID": "",  # random, eg: _b8e3193c-aa49-4c45-8ca5-1c74d7de11b2
    "NameIDNameQualifier": NameIDNameQualifier,
    "NameID": "",  # random, eg: _3fc08efa-a851-4855-9f03-9b881df8ca06
    "NotOnOrAfter": "",  # 2021-03-04T15:53:37Z
    "NotBefore": "",  # 2021-03-04T15:48:46Z -> IssueInstant
    "AuthnIstant": "",  # 2021-03-04T15:48:46Z ~ IssueInstant
    "SessionIndex": "",  # _ffa3114b-f589-417b-8602-4b0275f6bafc
    "AuthnContextClassRef": "https://www.spid.gov.it/SpidL1",
    "Attributes": ATTRIBUTES,
    "sign_response": True,
    "sign_assertion": True,
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
            <ds:Reference {% if ReferenceURI %} URI="{{ReferenceURI}}" {% endif %}>
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
                    <ds:DigestValue />
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue />

        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate />
            </ds:X509Data>
        </ds:KeyInfo>

    </ds:Signature>
"""

# SIGNATURE_TMPL = """
# <ds:Signature>
# <ds:SignedInfo>
# <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
# <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
# <ds:Reference>
# <ds:Transforms>
# <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
# <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
# </ds:Transforms>
# <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
# <ds:DigestValue />
# </ds:Reference>
# </ds:SignedInfo>
# <ds:SignatureValue />
# </ds:Signature>
# """

RESPONSE_TESTS = {
    "1": {
        "name": "01. Response corretta",
        "description": "Response corretta. Risultato atteso: Ok",
        "status_codes": [200],
        "path": "base.xml",
        "response": {},
    },
    "2": {
        "name": "02. Response non firmata",
        "description": "Response non firmata. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-02.xml",
        "response": {},
    },
    "3": {
        "name": "03. Response - Assertion non firmata",
        "description": "Response firmata, Assertion non firmata. (L'assertion deve essere sempre firmata, la response può essere firmata). Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-03.xml",
        "response": {},
    },
    "4": {
        "name": "04. Response - Firma non valida",
        "description": "Response firmata con certificato diverso da quello registrato su SP. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "base.xml",
        "response": {},
        "sign_credentials": {
            "certificate": f"{BASE_DIR}/certificates/test_public.cert",
            "privateKey": f"{BASE_DIR}/certificates/test_private.key",
        },
    },
    "5": {
        "name": "05. Response - Firma non valida con presenza x509 alternativo",
        "description": "Response firmata con certificato diverso da quello registrato su SP, con x509 presente nella Response. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "base.xml",
        "response": {
            "X509Certificate": f"{BASE_DIR}/certificates/test_public.cert",
        },
        "sign_credentials": {
            "certificate": f"{BASE_DIR}/certificates/test_public.cert",
            "privateKey": f"{BASE_DIR}/certificates/test_private.key",
        },
    },
    "xsw1": {
        "name": "xsw1. Wrapping attack",
        "description": "XSW1 Wrapping attack. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "base.xml",
        "response": {
            "X509Certificate": f"{BASE_DIR}/certificates/test_public.cert",
        },
        "response_wrappers": ["spid_sp_test.responses.response_wraps.xsw1"],
    },
    "xsw2": {
        "name": "xsw2. Wrapping attack",
        "description": "XSW2 Wrapping attack. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "base.xml",
        "response": {
            "X509Certificate": f"{BASE_DIR}/certificates/test_public.cert",
        },
        "response_wrappers": ["spid_sp_test.responses.response_wraps.xsw2"],
    },
    "xsw3": {
        "name": "xsw3. Wrapping attack",
        "description": "XSW3 Wrapping attack. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "base.xml",
        "response": {
            "X509Certificate": f"{BASE_DIR}/certificates/test_public.cert",
        },
        "response_wrappers": ["spid_sp_test.responses.response_wraps.xsw3"],
    },
    "xsw4": {
        "name": "xsw4. Wrapping attack",
        "description": "XSW4 Wrapping attack. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "base.xml",
        "response": {
            "X509Certificate": f"{BASE_DIR}/certificates/test_public.cert",
        },
        "response_wrappers": ["spid_sp_test.responses.response_wraps.xsw4"],
    },
    "xsw5": {
        "name": "xsw5. Wrapping attack",
        "description": "XSW5 Wrapping attack. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "base.xml",
        "response": {
            "X509Certificate": f"{BASE_DIR}/certificates/test_public.cert",
        },
        "response_wrappers": ["spid_sp_test.responses.response_wraps.xsw5"],
    },
    "xsw6": {
        "name": "xsw6. Wrapping attack",
        "description": "XSW6 Wrapping attack. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "base.xml",
        "response": {
            "X509Certificate": f"{BASE_DIR}/certificates/test_public.cert",
        },
        "response_wrappers": ["spid_sp_test.responses.response_wraps.xsw6"],
    },
    "xsw7": {
        "name": "xsw7. Wrapping attack",
        "description": "XSW7 Wrapping attack. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "base.xml",
        "response": {
            "X509Certificate": f"{BASE_DIR}/certificates/test_public.cert",
        },
        "response_wrappers": ["spid_sp_test.responses.response_wraps.xsw7"],
    },
    "xsw8": {
        "name": "xsw8. Wrapping attack",
        "description": "XSW8 Wrapping attack. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "base.xml",
        "response": {
            "X509Certificate": f"{BASE_DIR}/certificates/test_public.cert",
        },
        "response_wrappers": ["spid_sp_test.responses.response_wraps.xsw8"],
    },
    # "xxe": {
    # "name": "XXE. attack",
    # "description": "XXE attack. Risultato atteso: KO",
    # "status_codes": HTTP_STATUS_ERROR_CODES,
    # "path": "xxe.xml",
    # "response": {},
    # },
    "xslt": {
        "name": "XSLT. attack",
        "description": "XSLT attack. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "base.xml",
        "response_wrappers": ["spid_sp_test.responses.response_wraps.xslt"],
    },
    "8": {
        "name": "08. Response - ID non specificato",
        "description": "Attributo ID non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-08.xml",
        "response": {"ResponseID": None},
    },
    "9": {
        "name": "09. Response - ID mancante",
        "description": "Attributo ID mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-09.xml",
        "response": {"ResponseID": None},
    },
    "10": {
        "name": "10. Response - Version diverso da 2.0",
        "description": "Attributo Version diverso da 2.0. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-10.xml",
        "response": {},
    },
    "11": {
        "name": "11. Response - IssueInstant non specificato",
        "description": "Attributo IssueInstant non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-11.xml",
        "response": {
            "IssueInstant": "",
        },
    },
    "12": {
        "name": "12. Response - IssueInstant mancante",
        "description": "Attributo IssueInstant mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-12.xml",
        "response": {},
    },
    "13": {
        "name": "13. Response - Formato IssueInstant non corretto",
        "description": "Attributo IssueInstant avente formato non corretto. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-13.xml",
        "response": {},
    },
    "14": {
        "name": "14. Response - IssueInstant precedente Request",
        "description": "Attributo IssueInstant precedente a IssueInstant della request. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "base.xml",
        "response": {
            "IssueInstant": "2018-01-01T00:00:00Z",
        },
    },
    "15": {
        "name": "15. Response - IssueInstant successivo Request",
        "description": "Attributo IssueInstant successivo all'istante di ricezione. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "base.xml",
        "response": {
            "IssueInstant": "2099-01-01T00:00:00Z",
        },
    },
    "16": {
        "name": "16. Response - InResponseTo non specificato",
        "description": "Attributo InResponseTo non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-16.xml",
        "response": {"InResponseTo": ""},
    },
    "17": {
        "name": "17. Response - InResponseTo mancante",
        "description": "Attributo InResponseTo mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-17.xml",
        "response": {},
    },
    "18": {
        "name": "18. Response - InResponseTo diverso da Request",
        "description": "Attributo InResponseTo diverso da ID request. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "base.xml",
        "response": {
            "AuthnRequestID": "inresponsetodiversodaidrequest",
        },
    },
    "19": {
        "name": "19. Response - Destination non specificato",
        "description": "Attributo Destination non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-19.xml",
        "response": {},
    },
    "20": {
        "name": "20. Response - Destination mancante",
        "description": "Attributo Destination mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-20.xml",
        "response": {},
    },
    "21": {
        "name": "21. Response - Destination diverso da AssertionConsumerServiceURL",
        "description": "Attributo Destination diverso da AssertionConsumerServiceURL. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-21.xml",
        "response": {"AssertionConsumerURL": "diversodaassertionconsumerserviceurl"},
    },
    "22": {
        "name": "22. Response - Elemento Status non specificato",
        "description": "Elemento Status non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-22.xml",
        "response": {},
    },
    "23": {
        "name": "23. Response - Elemento Status mancante",
        "description": "Elemento Status mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-23.xml",
        "response": {},
    },
    "24": {
        "name": "24. Response - Elemento StatusCode non specificato",
        "description": "Elemento StatusCode non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-24.xml",
        "response": {},
    },
    # identico al 22
    # "25": {
    # "name": "25. Response - Elemento StatusCode mancante",
    # "description": "Elemento StatusCode mancante. Risultato atteso: KO",
    # "status_codes": HTTP_STATUS_ERROR_CODES,
    # "path": "case-25.xml",
    # "response": {},
    # },
    "26": {
        "name": "26. Response - Elemento StatusCode diverso da success (non valido)",
        "description": "Elemento StatusCode diverso da Success (non valido). Risultato atteso: KO. il S.P. deve mostrare schermata di errore",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-26.xml",
        "response": {},
    },
    "27": {
        "name": "27. Response - Elemento Issuer non specificato",
        "description": "Elemento Issuer non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-27.xml",
        "response": {},
    },
    "28": {
        "name": "28. Response - Elemento Issuer mancante",
        "description": "Elemento Issuer mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-28.xml",
        "response": {},
    },
    "29": {
        "name": "29. Response - Elemento Assertion Issuer diverso da EntityID IdP",
        "description": "Elemento Issuer diverso da EntityID IdP. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-29.xml",
        "response": {},
    },
    "30": {
        "name": "30. Response - Attributo Format di Issuer diverso",
        "description": "L'attributo Format di Issuer della Response deve essere omesso o assumere valore urn:oasis:names:tc:SAML:2.0:nameid-format:entity. In questo test il valore è diverso. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-30.xml",
        "response": {},
    },
    "31": {
        "name": "31. Response - Attributo Format di Issuer omesso",
        "description": "L'attributo Format di Issuer della Response deve essere omesso o assumere valore urn:oasis:names:tc:SAML:2.0:nameid-format:entity. In questo test il valore è omesso. Risultato atteso: Ok",
        "status_codes": [200],
        "path": "case-31.xml",
        "response": {},
    },
    "32": {
        "name": "32. Response - Elemento Assertion mancante",
        "description": "Elemento Assertion mancante ed esito positivo autenticazione. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-32.xml",
        "response": {"AssertionID": None},
    },
    "33": {
        "name": "33. Assertion - Attributo ID non specificato",
        "description": "Attributo ID dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-33.xml",
        "response": {"AssertionID": None},
    },
    "34": {
        "name": "34. Assertion - Attributo ID mancante",
        "description": "Attributo ID dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-34.xml",
        "response": {"AssertionID": None},
    },
    "35": {
        "name": "35. Assertion - Attributo Version diverso da 2.0",
        "description": "Attributo Version dell'Assertion diverso da 2.0. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-35.xml",
        "response": {},
    },
    "36": {
        "name": "36. Assertion - Attributo IssueInstant non specificato",
        "description": "Attributo IssueInstant dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-36.xml",
        "response": {},
    },
    "37": {
        "name": "37. Assertion - Attributo IssueInstant mancante",
        "description": "Attributo IssueInstant dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-37.xml",
        "response": {},
    },
    "38": {
        "name": "38. Assertion - Attributo IssueInstant avente formato non corretto",
        "description": "Attributo IssueInstant dell'Assertion avente formato non corretto. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-38.xml",
        "response": {},
    },
    "39": {
        "name": "39. Assertion - Attributo IssueInstant precedente a IssueInstant della Request",
        "description": "Attributo IssueInstant dell'Assertion precedente a IssueInstant della Request. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-39.xml",
        "response": {},
    },
    "40": {
        "name": "40. Assertion - Attributo IssueInstant successivo a IssueInstant della Request",
        "description": "Attributo IssueInstant dell'Assertion successivo a IssueInstant della Request. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-40.xml",
        "response": {},
    },
    "41": {
        "name": "41. Assertion - Elemento Subject non specificato",
        "description": "Elemento Subject dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-41.xml",
        "response": {},
    },
    "42": {
        "name": "42. Assertion - Elemento Subject mancante",
        "description": "Elemento Subject dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-42.xml",
        "response": {},
    },
    "43": {
        "name": "43. Assertion - Elemento NameID non specificato",
        "description": "Elemento NameID dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-43.xml",
        "response": {},
    },
    "44": {
        "name": "44. Assertion - Elemento NameID mancante",
        "description": "Elemento NameID dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-44.xml",
        "response": {},
    },
    "45": {
        "name": "45. Assertion - Attributo Format di NameID non specificato",
        "description": "Attributo Format dell'elemento NameID dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-45.xml",
        "response": {},
    },
    "46": {
        "name": "46. Assertion - Attributo Format di NameID mancante",
        "description": "Attributo Format dell'elemento NameID dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-46.xml",
        "response": {},
    },
    "47": {
        "name": "47. Assertion - Attributo Format di NameID diverso",
        "description": "Attributo Format di NameID dell'Assertion diverso da urn:oasis:names:tc:SAML:2.0:nameidformat:transient. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-47.xml",
        "response": {},
    },
    "48": {
        "name": "48. Assertion - Attributo NameQualifier di NameID non specificato",
        "description": "Attributo NameQualifier di NameID dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-48.xml",
        "response": {},
    },
    "49": {
        "name": "49. Assertion - Attributo NameQualifier di NameID mancante",
        "description": "Attributo NameQualifier di NameID dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-49.xml",
        "response": {},
    },
    "51": {
        "name": "51. Assertion - Elemento SubjectConfirmation non specificato",
        "description": "Elemento SubjectConfirmation dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-51.xml",
        "response": {},
    },
    "52": {
        "name": "52. Assertion - Elemento SubjectConfirmation mancante",
        "description": "Elemento SubjectConfirmation dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-52.xml",
        "response": {},
    },
    "53": {
        "name": "53. Assertion - Attributo Method di SubjectConfirmation non specificato",
        "description": "Attributo Method di SubjectConfirmation dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-53.xml",
        "response": {},
    },
    "54": {
        "name": "54. Assertion - Attributo Method di SubjectConfirmation mancante",
        "description": "Attributo Method di SubjectConfirmation dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-54.xml",
        "response": {},
    },
    "55": {
        "name": "55. Assertion - Attributo Method di SubjectConfirmation diverso",
        "description": "Attributo Method di SubjectConfirmation dell'Assertion diverso da urn:oasis:names:tc:SAML:2.0:cm:bearer. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-55.xml",
        "response": {},
    },
    "56": {
        "name": "56. Assertion - Elemento SubjectConfirmationData mancante",
        "description": "Elemento SubjectConfirmationData dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-56.xml",
        "response": {},
    },
    "57": {
        "name": "57. Assertion - Attributo Recipient di SubjectConfirmationData non specificato",
        "description": "Attributo Recipient di SubjectConfirmationData dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-57.xml",
        "response": {},
    },
    "58": {
        "name": "58. Assertion - Attributo Recipient di SubjectConfirmationData mancante",
        "description": "Attributo Recipient di SubjectConfirmationData dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-58.xml",
        "response": {},
    },
    "59": {
        "name": "59. Assertion - Attributo Recipient di SubjectConfirmationData diverso",
        "description": "Attributo Recipient di SubjectConfirmationData dell'Assertion diverso da AssertionConsumerServiceURL. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-59.xml",
        "response": {},
    },
    "60": {
        "name": "60. Assertion - Attributo InResponseTo di SubjectConfirmationData non specificato",
        "description": "Attributo InResponseTo di SubjectConfirmationData dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-60.xml",
        "response": {},
    },
    "61": {
        "name": "61. Assertion - Attributo InResponseTo di SubjectConfirmationData mancante",
        "description": "Attributo InResponseTo di SubjectConfirmationData dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-61.xml",
        "response": {},
    },
    "62": {
        "name": "62. Assertion - Attributo InResponseTo di SubjectConfirmationData diverso da ID request",
        "description": "Attributo InResponseTo di SubjectConfirmationData dell'Assertion diverso da ID request. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-62.xml",
        "response": {},
    },
    "63": {
        "name": "63. Assertion - Attributo NotOnOrAfter di SubjectConfirmationData non specificato",
        "description": "Attributo NotOnOrAfter di SubjectConfirmationData dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-63.xml",
        "response": {},
    },
    "64": {
        "name": "64. Assertion - Attributo NotOnOrAfter di SubjectConfirmationData mancante",
        "description": "Attributo NotOnOrAfter di SubjectConfirmationData mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-64.xml",
        "response": {},
    },
    "65": {
        "name": "65. Assertion - Attributo NotOnOrAfter di SubjectConfirmationData avente formato non corretto",
        "description": "Attributo NotOnOrAfter di SubjectConfirmationData avente formato non corretto. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-65.xml",
        "response": {},
    },
    "66": {
        "name": "66. Assertion - Attributo NotOnOrAfter di SubjectConfirmationData precedente all'istante di ricezione della response",
        "description": "Attributo NotOnOrAfter di SubjectConfirmationData precedente all'istante di ricezione della response. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-66.xml",
        "response": {},
    },
    # identico al 29
    # "67": {
    # "name": "67. Assertion - Elemento Issuer non specificato",
    # "description": "Elemento Issuer dell'Assertion non specificato. Risultato atteso: KO",
    # "status_codes": HTTP_STATUS_ERROR_CODES,
    # "path": "case-67.xml",
    # "response": {},
    #
    #
    # },
    "68": {
        "name": "68. Assertion - Elemento Issuer mancante",
        "description": "Elemento Issuer dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-68.xml",
        "response": {},
    },
    "69": {
        "name": "69. Assertion - Elemento Issuer diverso da EntityID IdP",
        "description": "Elemento Issuer dell'Assertion diverso da EntityID IdP. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-69.xml",
        "response": {},
    },
    "70": {
        "name": "70. Assertion - Attributo Format di Issuer non specificato",
        "description": "Attributo Format di Issuer dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-70.xml",
        "response": {},
    },
    "71": {
        "name": "71. Assertion - Attributo Format di Issuer mancante",
        "description": "Attributo Format di Issuer dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-71.xml",
        "response": {},
    },
    "72": {
        "name": "72. Assertion - Attributo Format di Issuer diverso",
        "description": "L'attributo Format di Issuer dell'Assertion deve essere presente con il valore urn:oasis:names:tc:SAML:2.0:nameid-format:entity. In questo test, invece, il valore è diverso. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-72.xml",
        "response": {},
    },
    "73": {
        "name": "73. Assertion - Elemento Conditions non specificato",
        "description": "Elemento Conditions dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-73.xml",
        "response": {},
    },
    "74": {
        "name": "74. Assertion - Elemento Conditions mancante",
        "description": "Elemento Conditions dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-74.xml",
        "response": {},
    },
    "75": {
        "name": "75. Assertion - Attributo NotBefore di Condition non specificato",
        "description": "Attributo NotBefore di Condition dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-75.xml",
        "response": {},
    },
    "76": {
        "name": "76. Assertion - Attributo NotBefore di Condition mancante",
        "description": "Attributo NotBefore di Condition dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-76.xml",
        "response": {},
    },
    "77": {
        "name": "77. Assertion - Attributo NotBefore di Condition avente formato non corretto",
        "description": "Attributo NotBefore di Condition dell'Assertion avente formato non corretto. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-77.xml",
        "response": {},
    },
    "78": {
        "name": "78. Assertion - Attributo NotBefore di Condition successivo all'instante di ricezione della response",
        "description": "Attributo NotBefore di Condition dell'Assertion successivo all'instante di ricezione della response. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-78.xml",
        "response": {},
    },
    "79": {
        "name": "79. Assertion - Attributo NotOnOrAfter di Condition non specificato",
        "description": "Attributo NotOnOrAfter di Condition dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-79.xml",
        "response": {},
    },
    "80": {
        "name": "80. Assertion - Attributo NotOnOrAfter di Condition mancante",
        "description": "Attributo NotOnOrAfter di Condition dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-80.xml",
        "response": {},
    },
    "81": {
        "name": "81. Assertion - Attributo NotOnOrAfter di Condition avente formato non corretto",
        "description": "Attributo NotOnOrAfter di Condition dell'Assertion avente formato non corretto. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-81.xml",
        "response": {},
    },
    "82": {
        "name": "82. Assertion - Attributo NotOnOrAfter di Condition precedente all'istante di ricezione della response",
        "description": "Attributo NotOnOrAfter di Condition dell'Assertion precedente all'istante di ricezione della response. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-82.xml",
        "response": {},
    },
    "83": {
        "name": "83. Assertion - Elemento AudienceRestriction di Condition non specificato",
        "description": "Elemento AudienceRestriction di Condition dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-83.xml",
        "response": {},
    },
    # identico al 73
    # "84": {
    # "name": "84. Assertion - Elemento AudienceRestriction di Condition mancante",
    # "description": "Elemento AudienceRestriction di Condition dell'Assertion mancante. Risultato atteso: KO",
    # "status_codes": HTTP_STATUS_ERROR_CODES,
    # "path": "case-84.xml",
    # "response": {},
    # },
    "85": {
        "name": "85. Assertion - Elemento Audience di AudienceRestriction di Condition non specificato",
        "description": "Elemento Audience di AudienceRestriction di Condition dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-85.xml",
        "response": {},
    },
    "86": {
        "name": "86. Assertion - Elemento Audience di AudienceRestriction di Condition mancante",
        "description": "Elemento Audience di AudienceRestriction di Condition dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-86.xml",
        "response": {},
    },
    "87": {
        "name": "87. Assertion - Elemento Audience di AudienceRestriction di Condition diverso da Entity Id del Service Provider",
        "description": "Elemento Audience di AudienceRestriction di Condition dell'Assertion diverso da Entity Id del Service Provider. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-87.xml",
        "response": {},
    },
    "88": {
        "name": "88. Assertion - Elemento AuthStatement non specificato",
        "description": "Elemento AuthStatement dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-88.xml",
        "response": {},
    },
    "89": {
        "name": "89. Assertion - Elemento AuthStatement mancante",
        "description": "Elemento AuthStatement dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-89.xml",
        "response": {},
    },
    "90": {
        "name": "90. Assertion - Elemento AuthnContext di AuthStatement non specificato",
        "description": "Elemento AuthnContext di AuthStatement dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-90.xml",
        "response": {},
    },
    # identico a 88
    # "91": {
    # "name": "91. Assertion - Elemento AuthnContext di AuthStatement mancante",
    # "description": "Elemento AuthnContext di AuthStatement dell'Assertion mancante. Risultato atteso: KO",
    # "status_codes": HTTP_STATUS_ERROR_CODES,
    # "path": "case-91.xml",
    # "response": {},
    # },
    "92": {
        "name": "92. Assertion - Elemento AuthContextClassRef di AuthnContext di AuthStatement non specificato",
        "description": "Elemento AuthContextClassRef di AuthnContext di AuthStatement dell'Assertion non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-92.xml",
        "response": {},
    },
    "93": {
        "name": "93. Assertion - Elemento AuthContextClassRef di AuthnContext di AuthStatement mancante",
        "description": "Elemento AuthContextClassRef di AuthnContext di AuthStatement dell'Assertion mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-93.xml",
        "response": {},
    },
    "94": {
        "name": "94. Assertion - Elemento AuthContextClassRef impostato su https://www.spid.gov.it/SpidL1",
        "description": "Elemento AuthContextClassRef impostato su https://www.spid.gov.it/SpidL1. Il SP ha accettato un ACR non compatibile con Comparison e non superiore.",
        "status_codes": [200],
        "path": "base.xml",
        "response": {
            "AuthnContextClassRef": "https://www.spid.gov.it/SpidL1",
            "Attributes": ATTRIBUTES,
        },
        "response_mods": ["spid_sp_test.responses.response_mods.dynamic_acr"],
    },
    "95": {
        "name": "95. Assertion - Elemento AuthContextClassRef impostato su https://www.spid.gov.it/SpidL2",
        "description": "Elemento AuthContextClassRef impostato su https://www.spid.gov.it/SpidL2. Il SP ha accettato un ACR non compatibile con Comparison e non superiore.",
        "status_codes": [200],
        "path": "base.xml",
        "response": {
            "AuthnContextClassRef": "https://www.spid.gov.it/SpidL2",
        },
        "response_mods": ["spid_sp_test.responses.response_mods.dynamic_acr"],
    },
    "96": {
        "name": "96. Assertion - Elemento AuthContextClassRef impostato su https://www.spid.gov.it/SpidL3",
        "description": "Elemento AuthContextClassRef impostato su https://www.spid.gov.it/SpidL3. Il SP ha accettato un ACR non compatibile con Comparison e non superiore.",
        "status_codes": [200],
        "path": "base.xml",
        "response": {
            "AuthnContextClassRef": "https://www.spid.gov.it/SpidL3",
        },
        "response_mods": ["spid_sp_test.responses.response_mods.dynamic_acr"],
    },
    "97": {
        "name": "97. Assertion - Elemento AuthContextClassRef impostato ad un valore non previsto",
        "description": "Elemento AuthContextClassRef impostato ad un valore non previsto. Es. specifica precedente. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "base.xml",
        "response": {
            "AuthnContextClassRef": "urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL1",
        },
    },
    "98": {
        "name": "98. Assertion - Elemento AttributeStatement presente, ma sottoelemento Attribute mancante ",
        "description": "Elemento AttributeStatement presente, ma sottoelemento Attribute mancante. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-98.xml",
        "response": {},
    },
    "99": {
        "name": "99. Assertion - Elemento AttributeStatement presente, con sottoelemento Attribute non specificato",
        "description": "Elemento AttributeStatement presente, ma sottoelemento Attribute non specificato. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-99.xml",
        "response": {},
    },
    # todo
    "100": {
        "name": "100. Assertion - Firma diversa",
        "description": "Assertion firmata con certificato diverso. Risultato atteso: KO",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "base.xml",
        "response": {},
        "sign_credentials": {
            "certificate": f"{BASE_DIR}/certificates/test_public.cert",
            "privateKey": f"{BASE_DIR}/certificates/test_private.key",
        },
    },
    "103": {
        "name": "103. Assertion - Set di attributi inviato diverso da quello richiesto",
        "description": "Set di attributi inviato diverso da quello richiesto",
        "status_codes": [200, 400, 403, 500],
        "path": "base.xml",
        "response": {"Attributes": {"spidCode": "AGID-001", "address": "via Test"}},
    },
    "104": {
        "name": "104. Anomalie utente - Ripetuta sottomissione di credenziali errate (Anomalia 19)",
        "description": "Elemento StatusCode ErrorCode nr19. Autenticazione fallita per ripetuta sottomissione di credenziali errate. Risultato atteso: KO. il S.P. deve mostrare schermata di errore",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-anomalie-utente.xml",
        "response": {
            "StatusCode": "urn:oasis:names:tc:SAML:2.0:status:Responder",
            "SubStatus": "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            "StatusMessage": "ErrorCode nr19",
        },
    },
    "105": {
        "name": "105. Anomalie utente - Utente privo di credenziali compatibili (Anomalia 20)",
        "description": "Elemento StatusCode ErrorCode nr20. Utente privo di credenziali compatibili con il livello richiesto dal fornitore del servizio. Risultato atteso: KO. il S.P. deve mostrare schermata di errore",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-anomalie-utente.xml",
        "response": {
            "StatusCode": "urn:oasis:names:tc:SAML:2.0:status:Responder",
            "SubStatus": "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            "StatusMessage": "ErrorCode nr20",
        },
    },
    "106": {
        "name": "106. Anomalie utente - Timeout (Anomalia 21)",
        "description": "Elemento StatusCode ErrorCode nr21. Timeout durante l'autenticazione utente. Risultato atteso: KO. il S.P. deve mostrare schermata di errore",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-anomalie-utente.xml",
        "response": {
            "StatusCode": "urn:oasis:names:tc:SAML:2.0:status:Responder",
            "SubStatus": "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            "StatusMessage": "ErrorCode nr21",
        },
    },
    "107": {
        "name": "107. Anomalie utente - Consenso negato (Anomalia 22)",
        "description": "Elemento StatusCode ErrorCode nr22. Utente nega il consenso all'invio di dati al SP in caso di sessione vigente. Risultato atteso: KO. il S.P. deve mostrare schermata di errore",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-anomalie-utente.xml",
        "response": {
            "StatusCode": "urn:oasis:names:tc:SAML:2.0:status:Responder",
            "SubStatus": "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            "StatusMessage": "ErrorCode nr22",
        },
    },
    "108": {
        "name": "108. Anomalie utente - Credenziali bloccate (Anomalia 23)",
        "description": "Elemento StatusCode ErrorCode nr23. Utente con identità sospesa/revocata o con credenziali bloccate. Risultato atteso: KO. il S.P. deve mostrare schermata di errore",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-anomalie-utente.xml",
        "response": {
            "StatusCode": "urn:oasis:names:tc:SAML:2.0:status:Responder",
            "SubStatus": "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            "StatusMessage": "ErrorCode nr23",
        },
    },
    "109": {
        "name": "109. Attributi senza NameFormat",
        "description": "Response corretta. Risultato atteso: Ok",
        "status_codes": [200],
        "path": "case-109.xml",
        "response": {},
        "attributesNameFormat": False,
    },
    "110": {
        "name": "110. Response - IssueInstant con millisecondi",
        "description": "Attributo IssueInstant specificato con millisecondi. Risultato atteso: Ok",
        "status_codes": [200],
        "path": "case-110.xml",
        "response": {},
    },
    "111": {
        "name": "111. Anomalie utente - Processo di autenticazione annullato dall'utente (Anomalia 25)",
        "description": "Elemento StatusCode ErrorCode nr25. Processo di autenticazione annullato dall'utente. Risultato atteso: KO. il S.P. deve mostrare schermata di errore",
        "status_codes": HTTP_STATUS_ERROR_CODES,
        "path": "case-anomalie-utente.xml",
        "response": {
            "StatusCode": "urn:oasis:names:tc:SAML:2.0:status:Responder",
            "SubStatus": "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            "StatusMessage": "ErrorCode nr25",
        },
    },
}


TEST_SUITE = {
    "test-suite-1": {
        "description": "Test Response",
        "response": {
            "AssertionConsumerURL": "",
            "ResponseID": "",
            "AuthnRequestID": "",
        },
        "cases": RESPONSE_TESTS,
    },
    "test-logout": {
        "description": "Test Logout Response",
        "response": {
            "ResponseID": "",
            "IssueInstant": "",
            "Destination": "",
            "AuthnRequestID": "",
            "NameQualifier": NameIDNameQualifier,
            "Issuer": "",
        },
        "cases": {
            "1": {
                "name": "01. Logout",
                "description": "Logout corretto",
                "path": "logout-1.xml",
                "response": {},
                "sign_response": True,
            }
        },
    },
}
