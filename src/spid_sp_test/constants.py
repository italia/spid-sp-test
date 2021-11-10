# Copyright 2019 AgID - Agenzia per l'Italia Digitale
#
# Licensed under the EUPL, Version 1.2 or - as soon they will be approved by
# the European Commission - subsequent versions of the EUPL (the "Licence").
#
# You may not use this work except in compliance with the Licence.
#
# You may obtain a copy of the Licence at:
#
# https://joinup.ec.europa.eu/software/page/eupl
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the Licence is distributed on an "AS IS" basis, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# Licence for the specific language governing permissions and limitations
# under the Licence.

import re

# iso8601 fully compliant regex
UTC_STRING = r"^(-?(?:[1-9][0-9]*)?[0-9]{4})-(1[0-2]|0[1-9])-(3[01]|0[1-9]|[12][0-9])T(2[0-3]|[01][0-9]):([0-5][0-9]):([0-5][0-9])(\.[0-9]+)?(Z|[+-](?:2[0-3]|[01][0-9]):[0-5][0-9])?$"  # noqa

UTC_REGEXP = re.compile(UTC_STRING)

HTTP_NO_PORT_REGEX = re.compile(
    r"^(?:http)s?://"  # http:// or https://
    r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)"  # domain...
    # r'|localhost|' #localhost...
    # r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' # ...or ip
    r")"
    # r'(?::\d+)?' # optional port
    r"(?:/?|[/?]\S+)$",
    re.IGNORECASE,
)

_SPID_LEVEL_23 = r"(https:\/\/www\.spid\.gov\.it\/)SpidL[2-3]"  # noqa
SPID_LEVEL_23 = re.compile(_SPID_LEVEL_23)

_SPID_LEVEL_ALL = r"(https:\/\/www\.spid\.gov\.it\/)SpidL[1-3]"  # noqa
SPID_LEVEL_ALL = re.compile(_SPID_LEVEL_ALL)

BOOLEAN_TRUE = [
    "true",
    "1",
]

ALLOWED_BINDINGS = [
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
]

ALLOWED_SINGLELOGOUT_BINDINGS = [
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
    "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
]

ALLOWED_FORMATS = [
    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
    "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
]

ALLOWED_STATUS_CODES = [
    "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
    "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext",
    "urn:oasis:names:tc:SAML:2.0:status:NoPassive",
    "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
    "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported",
    "urn:oasis:names:tc:SAML:2.0:status:Requester",
    "urn:oasis:names:tc:SAML:2.0:status:Success",
    "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch",
]

ALLOWED_XMLDSIG_ALGS = [
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
]

ALLOWED_DGST_ALGS = [
    "http://www.w3.org/2001/04/xmlenc#sha256",
    "http://www.w3.org/2001/04/xmlenc#sha384",
    "http://www.w3.org/2001/04/xmlenc#sha512",
]

SPID_ATTRIBUTES = [
    "address",
    "companyName",
    "companyFiscalNumber",
    "countyOfBirth",
    "dateOfBirth",
    "digitalAddress",
    "email",
    "expirationDate",
    "familyName",
    "fiscalNumber",
    "gender",
    "idCard",
    "ivaCode",
    "mobilePhone",
    "name",
    "placeOfBirth",
    "registeredOffice",
    "spidCode",
    "domicileStreetAddress",
    "domicilePostalCode",
    "domicileMunicipality",
    "domicileProvince",
    "domicileNation",
]

CIE_ATTRIBUTES = ["dateOfBirth", "familyName", "fiscalNumber", "name"]

FICEP_MIN_ATTRIBUTES = [
    "fiscalNumber",
    "spidCode",
    "name",
    "familyName",
    "dateOfBirth",
]

FICEP_FULL_ATTRIBUTES = [
    *FICEP_MIN_ATTRIBUTES,
    "placeOfBirth",
    "address",
    "gender",
]

FICEP_MINIMUM_SET_SERVICENAME = "eIDAS Natural Person Minimum Attribute Set"
FICEP_FULL_SET_SERVICENAME = "eIDAS Natural Person Full Attribute Set"

SPID_LEVELS = [
    "https://www.spid.gov.it/SpidL1",
    "https://www.spid.gov.it/SpidL2",
    "https://www.spid.gov.it/SpidL3",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL1",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL2",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL3",
]

NOSESINDEX_ACRS = [
    "https://www.spid.gov.it/SpidL2",
    "https://www.spid.gov.it/SpidL3",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL2",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:SpidL3",
]

ONE_MONTH = 30
SIX_MONTHS = 182
ONE_YEAR = 365

MINIMUM_CERTIFICATE_LENGHT = 2048  # type: int
DESIRED_CERTIFICATE_LENGHT = 3072  # type: int

NODE_NAME = "urn:oasis:names:tc:SAML:2.0:assertion:Assertion"
EMAIL_REGEXP = r"^(\w|\.|\_|\-)+[@](\w|\_|\-|\.)+[.]\w{2,6}$"


ISO3166_CODES = [
    "AD",
    "AE",
    "AF",
    "AG",
    "AI",
    "AL",
    "AM",
    "AO",
    "AQ",
    "AR",
    "AS",
    "AT",
    "AU",
    "AW",
    "AX",
    "AZ",
    "BA",
    "BB",
    "BD",
    "BE",
    "BF",
    "BG",
    "BH",
    "BI",
    "BJ",
    "BL",
    "BM",
    "BN",
    "BO",
    "BQ",
    "BR",
    "BS",
    "BT",
    "BV",
    "BW",
    "BY",
    "BZ",
    "CA",
    "CC",
    "CD",
    "CF",
    "CG",
    "CH",
    "CI",
    "CK",
    "CL",
    "CM",
    "CN",
    "CO",
    "CR",
    "CU",
    "CV",
    "CW",
    "CX",
    "CY",
    "CZ",
    "DE",
    "DJ",
    "DK",
    "DM",
    "DO",
    "DZ",
    "EC",
    "EE",
    "EG",
    "EH",
    "ER",
    "ES",
    "ET",
    "FI",
    "FJ",
    "FK",
    "FM",
    "FO",
    "FR",
    "GA",
    "GB",
    "GD",
    "GE",
    "GF",
    "GG",
    "GH",
    "GI",
    "GL",
    "GM",
    "GN",
    "GP",
    "GQ",
    "GR",
    "GS",
    "GT",
    "GU",
    "GW",
    "GY",
    "HK",
    "HM",
    "HN",
    "HR",
    "HT",
    "HU",
    "ID",
    "IE",
    "IL",
    "IM",
    "IN",
    "IO",
    "IQ",
    "IR",
    "IS",
    "IT",
    "JE",
    "JM",
    "JO",
    "JP",
    "KE",
    "KG",
    "KH",
    "KI",
    "KM",
    "KN",
    "KP",
    "KR",
    "KW",
    "KY",
    "KZ",
    "LA",
    "LB",
    "LC",
    "LI",
    "LK",
    "LR",
    "LS",
    "LT",
    "LU",
    "LV",
    "LY",
    "MA",
    "MC",
    "MD",
    "ME",
    "MF",
    "MG",
    "MH",
    "MK",
    "ML",
    "MM",
    "MN",
    "MO",
    "MP",
    "MQ",
    "MR",
    "MS",
    "MT",
    "MU",
    "MV",
    "MW",
    "MX",
    "MY",
    "MZ",
    "NA",
    "NC",
    "NE",
    "NF",
    "NG",
    "NI",
    "NL",
    "NO",
    "NP",
    "NR",
    "NU",
    "NZ",
    "OM",
    "PA",
    "PE",
    "PF",
    "PG",
    "PH",
    "PK",
    "PL",
    "PM",
    "PN",
    "PR",
    "PS",
    "PT",
    "PW",
    "PY",
    "QA",
    "RE",
    "RO",
    "RS",
    "RU",
    "RW",
    "SA",
    "SB",
    "SC",
    "SD",
    "SE",
    "SG",
    "SH",
    "SI",
    "SJ",
    "SK",
    "SL",
    "SM",
    "SN",
    "SO",
    "SR",
    "SS",
    "ST",
    "SV",
    "SX",
    "SY",
    "SZ",
    "TC",
    "TD",
    "TF",
    "TG",
    "TH",
    "TJ",
    "TK",
    "TL",
    "TM",
    "TN",
    "TO",
    "TR",
    "TT",
    "TV",
    "TW",
    "TZ",
    "UA",
    "UG",
    "UM",
    "US",
    "UY",
    "UZ",
    "VA",
    "VC",
    "VE",
    "VG",
    "VI",
    "VN",
    "VU",
    "WF",
    "WS",
    "YE",
    "YT",
    "ZA",
    "ZM",
    "ZW",
]

XML_NAMESPACES = {"spid": "https://spid.gov.it/saml-extensions"}
