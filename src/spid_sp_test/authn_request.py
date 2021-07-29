import base64
import binascii
import copy
import logging
import os
import requests
import xmlschema
import sys
import subprocess
import urllib
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from lxml import etree
from spid_sp_test.utils import (
    del_ns,
    saml_from_htmlform,
    decode_authn_req_http_redirect,
)
from spid_sp_test.idp.settings import BASE as idp_eid, SAML2_IDP_CONFIG
from spid_sp_test import constants
from spid_sp_test import BASE_DIR, AbstractSpidCheck

from saml2.server import Server
from saml2.sigver import CryptoBackendXMLSecurity

# from saml2.sigver import CryptoBackendXmlSec1
sys.path.append(os.path.join(os.path.dirname(__file__), os.pardir))
from tempfile import NamedTemporaryFile

from .exceptions import SAMLRequestNotFound
from .utils import load_plugin


logger = logging.getLogger(__name__)


def build_authn_post_data(
    request: requests, authn_request, authn_request_str: str, authn_request_url: str
):
    # HTTP POST
    authn_request_str = request.content.decode() if request else authn_request_str
    form_dict = saml_from_htmlform(authn_request_str)
    data = dict()
    if form_dict:
        data["action"] = form_dict["action"]
        data["method"] = form_dict["method"]
        data["SAMLRequest"] = form_dict["SAMLRequest"]
        data["SAMLRequest_xml"] = base64.b64decode(form_dict["SAMLRequest"].encode())
        data["RelayState"] = form_dict["RelayState"]
    elif ":AuthnRequest " in authn_request_str:
        data = {
            "SAMLRequest_xml": authn_request_str.encode(),
            "SAMLRequest": base64.b64encode(authn_request),
            "RelayState": "/",
        }
    else:
        raise SAMLRequestNotFound(f"{authn_request_str}")
    return data


def build_authn_redirect_data(
    request: requests,
    authn_request,
    authn_request_str: str,
    authn_request_url: str,
    **kwargs,
):
    # HTTP-REDIRECT
    redirect = request.headers["Location"] if request else authn_request_str
    q_args = urllib.parse.splitquery(redirect)[1]
    authn_request = dict(urllib.parse.parse_qsl(q_args))

    if not authn_request.get("SAMLRequest"):
        logger.critical(
            "\nHTTP-REDIRECT without any SAMLRequest in. "
            "Is this SP behind a Proxy or is there any "
            f"DiscoveryService enabled? {authn_request}"
        )
        sys.exit(1)
    data = dict()
    data["SAMLRequest_redirect"] = redirect
    data["SAMLRequest"] = authn_request["SAMLRequest"]
    data["SAMLRequest_xml"] = decode_authn_req_http_redirect(
        authn_request["SAMLRequest"]
    ).encode()
    data["RelayState"] = authn_request.get("RelayState")
    data["SigAlg"] = authn_request["SigAlg"]
    data["Signature"] = authn_request["Signature"]
    return data


def get_authn_request(
    authn_request_url: str,
    verify_ssl: bool = False,
    authn_plugin: str = None,
    requests_session=None,
    request_method: str = "GET",
    request_body: dict = {},
    request_content_type: str = "data",
):
    """
    Detects the auth request url, if http/xml file or html file

    request_content_type can be data or json
    """
    data = {}
    request = None
    binding = "post" or "redirect"
    authn_request_str = None
    authn_request = ""

    # eg: auth_plugin = 'that.package.module.Class'
    requests_session = requests_session or requests.Session()
    if authn_plugin:
        func = load_plugin(authn_plugin)
        _ar = func(
            requests_session,
            authn_request_url,
            request_method,
            request_body,
            request_content_type,
        ).request()
        # if authn plugins made all the things ...
        if isinstance(_ar, dict):
            return _ar
        else:
            authn_request_url = _ar

    if authn_request_url[0:7] == "file://":
        authn_request = open(authn_request_url[7:], "rb").read().strip().strip(b"\n")
        # stupid test ... good enough for now
        authn_request_str = authn_request.decode()
        if authn_request_str[0] == "<" and authn_request_str[-1] == ">":
            binding = "post"
        elif "?" in authn_request_str and "&" in authn_request_str:
            binding = "redirect"
        else:
            raise Exception(f"Can't detect authn request from f{authn_request_url}")
    else:
        req_dict = {"verify": verify_ssl, "allow_redirects": False}
        # trigger the authn request
        if request_method.upper() == "GET":
            request = requests_session.get(authn_request_url, **req_dict)
        elif request_method.upper() == "POST":
            req_dict[request_content_type.lower()] = request_body
            request = requests_session.post(authn_request_url, **req_dict)
        else:
            raise NotImplementedError(request_method)

        if request.status_code not in (200, 302):
            raise Exception(
                (
                    "Authn Request page returns a HTML error "
                    f"code: {request.status_code}"
                )
            )
        elif request.headers.get("Location"):
            binding = "redirect"
        else:
            binding = "post"

    bdata = {"redirect": build_authn_redirect_data, "post": build_authn_post_data}
    _func = bdata[binding]
    if _func:
        data = _func(request, authn_request, authn_request_str, authn_request_url)
    else:
        raise SAMLRequestNotFound()

    # if requests_session:
    data["requests_session"] = requests_session
    return data


class SpidSpAuthnReqCheck(AbstractSpidCheck):
    xsds_files = [
        "saml-schema-protocol-2.0.xsd",
    ]

    def __init__(
        self,
        metadata,
        authn_request_url: str = None,
        authn_request: dict = {},
        xsds_files: list = None,
        xsds_files_path: str = None,
        production: bool = False,
        authn_plugin: str = None,
        request_method: str = "GET",
        request_body: dict = {},
        request_content_type: str = "data",
    ):

        super(SpidSpAuthnReqCheck, self).__init__(verify_ssl=production)
        self.category = "authnrequest_strict"

        self.logger = logger
        self.metadata = metadata

        try:
            self.authn_request = get_authn_request(
                authn_request_url,
                verify_ssl=production,
                authn_plugin=authn_plugin,
                request_method=request_method,
                request_body=request_body,
                request_content_type=request_content_type,
            )
        except binascii.Error as exp:
            _msg = "[2.0.0] Base64 decode of AuthnRequest MUST be correct"
            logger.critical(_msg + f": {exp}")
            self._assertTrue(False, _msg, description=exp)
            self.is_ok(f"{self.__class__.__name__}.test_xmldsig-pre")
            raise exp

        try:
            self.authn_request_decoded = self.authn_request["SAMLRequest_xml"]
            self.authn_request_encoded = self.authn_request["SAMLRequest"]

        except KeyError:
            raise SAMLRequestNotFound(self.authn_request)

        self.relay_state = self.authn_request.get("RelayState") or ""

        self.xsds_files = xsds_files or self.xsds_files
        self.xsds_files_path = xsds_files_path or f"{BASE_DIR}/xsd"

        self.md = etree.fromstring(self.metadata)
        del_ns(self.md)

        self.doc = etree.fromstring(self.authn_request_decoded)
        # clean up namespace (otherwise xpath doesn't work ...)
        del_ns(self.doc)

        # binding detection
        self.IS_HTTP_REDIRECT = self.authn_request.get("Signature")
        # HTTP-REDIRECT params
        self.params = {"RelayState": self.relay_state}
        self.production = production

    def idp(self):
        idp_config = copy.deepcopy(SAML2_IDP_CONFIG)
        idp_server = Server(idp_config)
        if self.metadata:
            idp_server.metadata.imp(
                [
                    {
                        "class": "saml2.mdstore.InMemoryMetaData",
                        "metadata": [(self.metadata,)],
                    }
                ]
            )
        return idp_server

    def test_xsd(self):
        """Test if the XSD validates and if the signature is valid"""

        _orig_pos = os.getcwd()
        os.chdir(self.xsds_files_path)
        authn_request = self.authn_request_decoded.decode()
        schema_file = open("saml-schema-protocol-2.0.xsd", "rb")
        msg = f"Test authn_request with {schema_file.name}"
        try:
            schema = xmlschema.XMLSchema(schema_file)
            if not schema.is_valid(authn_request):
                schema.validate(authn_request)
                self.handle_result("error", " ".join((msg, "-> FAILED!")))
                raise Exception("Validation Error")
            logger.info(" ".join((msg, "-> OK")))
        except Exception as e:
            os.chdir(_orig_pos)
            self.handle_result("error", "-> ".join((msg, f"{e}")))
        os.chdir(_orig_pos)

        return self.is_ok(f"{self.__class__.__name__}.test_xsd")

    def test_xmldsig(self):
        certs = self.md.xpath(
            '//SPSSODescriptor/KeyDescriptor[@use="signing"]'
            "/KeyInfo/X509Data/X509Certificate/text()"
        )

        desc = certs
        error_kwargs = dict(description=desc) if desc else {}

        msg = (
            "The AuthnRequest MUST validate against XSD "
            "and MUST have a valid signature"
        )

        if not certs:
            self.handle_result(
                "error",
                "-> ".join(
                    (
                        msg,
                        "AuthnRequest Signature validation failed: certificates are missing.",
                    ),
                    **error_kwargs,
                ),
            )
            return self.is_ok(f"{self.__class__.__name__}.test_xsd_and_xmldsig")
        else:
            is_valid = False
            for cert in certs:
                if self.IS_HTTP_REDIRECT:
                    with NamedTemporaryFile(suffix=".xml") as cert_file:
                        if cert[-1] != "\n":
                            cert += "\n"
                        cert_file.write(
                            f"-----BEGIN CERTIFICATE-----\n{cert}-----END CERTIFICATE-----".encode()
                        )
                        cert_file.seek(0)
                        _sigalg = self.authn_request.get("SigAlg", "")
                        quoted_req = urllib.parse.quote_plus(
                            self.authn_request["SAMLRequest"]
                        )
                        quoted_rs = urllib.parse.quote_plus(
                            self.authn_request.get("RelayState") or ""
                        )
                        quoted_sigalg = urllib.parse.quote_plus(_sigalg)
                        authn_req = (
                            f"SAMLRequest={quoted_req}&"
                            f"RelayState={quoted_rs}&"
                            f"SigAlg={quoted_sigalg}"
                        )

                        payload_file = NamedTemporaryFile(suffix=".xml")
                        payload_file.write(authn_req.encode())
                        payload_file.seek(0)

                        signature_file = NamedTemporaryFile(suffix=".sign")
                        signature_file.write(
                            base64.b64decode(self.authn_request["Signature"].encode())
                        )
                        signature_file.seek(0)

                        pubkey_file = NamedTemporaryFile(suffix=".crt")
                        x509_cert = subprocess.getoutput(
                            f"openssl x509 -in {cert_file.name} -noout -pubkey"
                        )
                        pubkey_file.write(x509_cert.encode())
                        pubkey_file.seek(0)

                        dgst = _sigalg.split("-")[-1]
                        signature = signature_file.name

                        ver_cmd = (
                            f"openssl dgst -{dgst} "
                            f"-verify {pubkey_file.name} "
                            f"-signature {signature} {payload_file.name}"
                        )
                        exit_msg = subprocess.getoutput(ver_cmd)
                        error_kwargs["description"] = exit_msg
                        if "Verified OK" in exit_msg:
                            is_valid = True
                        else:
                            is_valid = False

                else:
                    # pyXMLSecurity allows to pass a certificate without store it on a file
                    backend = CryptoBackendXMLSecurity()
                    is_valid = backend.validate_signature(
                        self.authn_request_decoded,
                        cert_file=cert,
                        cert_type="pem",
                        node_name=constants.NODE_NAME,
                        node_id=None,
                    )
                if is_valid:
                    break

        self._assertTrue(
            is_valid, "AuthnRequest Signature validation failed", **error_kwargs
        )
        return self.is_ok(f"{self.__class__.__name__}.test_xmldsig")


    def test_AuthnRequest(self):
        """Test the compliance of AuthnRequest element"""
        req = self.doc.xpath("/AuthnRequest")

        req_desc = [etree.tostring(ent).decode() for ent in req if req]
        error_kwargs = dict(description=req_desc) if req_desc else {}

        self._assertTrue(
            (len(req) == 1), "One AuthnRequest element MUST be present", **error_kwargs
        )
        if req:
            req = req[0]
        else:
            return self.is_ok(f"{self.__class__.__name__}.test_AuthnRequest")

        for attr in ("ID", "Version", "IssueInstant", "Destination"):
            self._assertTrue(
                (attr in req.attrib),
                f"The {attr} attribute MUST be present - TR pag. 8 ",
                **error_kwargs,
            )

            value = req.get(attr)
            if attr == "ID":
                self._assertIsNotNone(
                    value,
                    f"The {attr} attribute MUST have a value - TR pag. 8 ",
                    **error_kwargs,
                )

            if attr == "Version":
                exp = "2.0"
                self._assertEqual(
                    value,
                    exp,
                    f"The {attr} attribute MUST be {exp} - TR pag. 8 ",
                    **error_kwargs,
                )

            if attr == "IssueInstant":
                self._assertIsNotNone(
                    value,
                    f"The {attr} attribute MUST have a value - TR pag. 8 ",
                    **error_kwargs,
                )
                self._assertTrue(
                    bool(constants.UTC_STRING.search(value)),
                    f"The {attr} attribute MUST be a valid UTC string - TR pag. 8 ",
                    **error_kwargs,
                )

            if attr == "Destination":
                self._assertIsNotNone(
                    value,
                    f"The {attr} attribute MUST have a value - TR pag. 8 ",
                    **error_kwargs,
                )

                allowed_destinations = [
                    i[0]
                    for i in SAML2_IDP_CONFIG["service"]["idp"]["endpoints"][
                        "single_sign_on_service"
                    ]
                ]
                allowed_destinations.append(idp_eid)

                self._assertTrue(
                    (value in allowed_destinations),
                    "The Destination attribute SHOULD be the address to "
                    "which the request has been sent but can also be the EnityID of IdP (Av. SPID n.11)",
                    description=value,
                )

                if self.production:
                    self._assertIsValidHttpsUrl(
                        value,
                        f"The {attr} attribute MUST be a valid HTTPS url - TR pag. 8 ",
                        **error_kwargs,
                    )
                    self._assertHttpUrlWithoutPort(
                        value,
                        'The entityID attribute MUST not contains any custom tcp ports, eg: ":8000"',
                    )

        self._assertTrue(
            ("IsPassive" not in req.attrib),
            "The IsPassive attribute MUST not be present - TR pag. 9 ",
            **error_kwargs,
        )
        return self.is_ok(f"{self.__class__.__name__}.test_AuthnRequest")

    def test_AuthnRequest_SPID(self):
        """Test the compliance of AuthnRequest element"""
        req = self.doc.xpath("/AuthnRequest")[0]

        req_desc = [etree.tostring(ent).decode() for ent in req if req is not None]
        error_kwargs = dict(description=req_desc) if req_desc else {}

        acr = req.xpath("//RequestedAuthnContext/AuthnContextClassRef")
        acr_desc = [etree.tostring(_acr).decode() for _acr in acr]

        if acr:
            level = acr[0].text
            if bool(constants.SPID_LEVEL_23.search(level)):
                self._assertTrue(
                    ("ForceAuthn" in req.attrib),
                    "The ForceAuthn attribute MUST be present if SPID level > 1 - TR pag. 8 ",
                    description=acr_desc,
                )
                value = req.get("ForceAuthn")
                if value:
                    self._assertTrue(
                        (value.lower() in constants.BOOLEAN_TRUE),
                        "The ForceAuthn attribute MUST be true or 1 - TR pag. 8 ",
                        **error_kwargs,
                    )

        attr = "AssertionConsumerServiceIndex"
        acss = self.md.xpath(
            "//EntityDescriptor/SPSSODescriptor" "/AssertionConsumerService"
        )
        acss_desc = [etree.tostring(_acss).decode() for _acss in acss]

        if attr in req.attrib:
            value = req.get(attr)
            availableassertionindexes = []

            for acs in acss:
                index = acs.get("index")
                availableassertionindexes.append(index)

            self._assertTrue(
                value in availableassertionindexes,
                f"The {attr} attribute MUST be equal to an AssertionConsumerService index - TR pag. 8 ",
                description=acss_desc,
            )

            self._assertIsNotNone(
                value,
                f"The {attr} attribute MUST have a value- TR pag. 8 ",
                **error_kwargs,
            )
            self._assertGreaterEqual(
                int(value),
                0,
                f"The {attr} attribute MUST be >= 0 - TR pag. 8 and pag. 20",
                **error_kwargs,
            )

        else:
            availableassertionlocations = []

            for acs in acss:
                location = acs.get("Location")
                availableassertionlocations.append(location)

            for attr in ["AssertionConsumerServiceURL", "ProtocolBinding"]:
                self._assertTrue(
                    (attr in req.attrib),
                    f"The {attr} attribute MUST be present - TR pag. 8 ",
                    **error_kwargs,
                )

                value = req.get(attr)
                self._assertIsNotNone(
                    value,
                    f"The {attr} attribute MUST have a value - TR pag. 8 ",
                    **error_kwargs,
                )

                if attr == "AssertionConsumerServiceURL":
                    if self.production:
                        self._assertIsValidHttpsUrl(
                            value,
                            f"The {attr} attribute MUST be a valid HTTPS url - TR pag. 8 and pag. 16",
                            **error_kwargs,
                        )
                        self._assertHttpUrlWithoutPort(
                            value,
                            'The entityID attribute MUST not contains any custom tcp ports, eg: ":8000"',
                        )
                    self._assertTrue(
                        value in availableassertionlocations,
                        f"The {attr} attribute MUST be equal to an AssertionConsumerService Location - TR pag. 8 ",
                        **error_kwargs,
                    )

                if attr == "ProtocolBinding":
                    exp = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    self._assertEqual(
                        value,
                        exp,
                        f"The {attr} attribute MUST be {exp} - TR pag. 8 ",
                        **error_kwargs,
                    )

        attr = "AttributeConsumingServiceIndex"
        if attr in req.attrib:
            availableattributeindexes = []

            acss = self.md.xpath(
                "//EntityDescriptor/SPSSODescriptor" "/AttributeConsumingService"
            )
            for acs in acss:
                index = acs.get("index")
                availableattributeindexes.append(index)

            value = req.get(attr)
            self._assertIsNotNone(
                value,
                f"The {attr} attribute MUST have a value - TR pag. 8",
                **error_kwargs,
            )
            self._assertGreaterEqual(
                int(value),
                0,
                f"The {attr} attribute MUST be >= 0 - TR pag. 8 and pag. 20",
                **error_kwargs,
            )
            self._assertTrue(
                value in availableattributeindexes,
                f"The {attr} attribute MUST be equal to an AttributeConsumingService index - TR pag. 8 ",
                **error_kwargs,
            )
        return self.is_ok(f"{self.__class__.__name__}.test_AuthnRequest_SPID")


    def test_Subject(self):
        """Test the compliance of Subject element"""

        subj = self.doc.xpath("//AuthnRequest/Subject")

        desc = [etree.tostring(ent).decode() for ent in subj if subj]
        error_kwargs = dict(description=desc) if desc else {}

        if len(subj) > 1:
            self._assertEqual(
                len(subj),
                1,
                "Only one Subject element can be present - TR pag. 9",
                **error_kwargs,
            )

        if len(subj) == 1:
            subj = subj[0]
            name_id = subj.xpath("./NameID")
            self._assertEqual(
                len(name_id),
                1,
                "One NameID element in Subject element MUST be present - TR pag. 9",
                **error_kwargs,
            )
            name_id = name_id[0]
            for attr in ["Format", "NameQualifier"]:
                self._assertTrue(
                    (attr in name_id.attrib),
                    f"The {attr} attribute MUST be present - TR pag. 9",
                    **error_kwargs,
                )

                value = name_id.get(attr)

                self._assertIsNotNone(
                    value,
                    f"The {attr} attribute MUST have a value - TR pag. 9",
                    **error_kwargs,
                )

                if attr == "Format":
                    exp = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
                    self._assertEqual(
                        value,
                        exp,
                        f"The {attr} attribute MUST be {exp} - TR pag. 9",
                        **error_kwargs,
                    )
        return self.is_ok(f"{self.__class__.__name__}.test_Subject")

    def test_Issuer(self):
        """Test the compliance of Issuer element"""
        e = self.doc.xpath("//AuthnRequest/Issuer")

        desc = [etree.tostring(ent).decode() for ent in e if e]
        error_kwargs = dict(description=desc) if desc else {}

        self._assertTrue(
            (len(e) == 1),
            "One Issuer element MUST be present - TR pag. 9",
            error_kwargs,
        )

        if not e:
            return self.is_ok(f"{self.__class__.__name__}.test_AuthnRequest")
        else:
            e = e[0]

        self._assertIsNotNone(
            e.text, "The Issuer element MUST have a value - TR pag. 9", **error_kwargs
        )

        entitydescriptor = self.md.xpath("//EntityDescriptor")
        entityid = entitydescriptor[0].get("entityID")
        self._assertEqual(
            e.text,
            entityid,
            "The Issuer's value MUST be equal to entityID - TR pag. 9",
            **error_kwargs,
        )

        for attr in ["Format", "NameQualifier"]:
            self._assertTrue(
                (attr in e.attrib),
                f"The {attr} attribute MUST be present - TR pag. 9",
                **error_kwargs,
            )

            value = e.get(attr)

            self._assertIsNotNone(
                value,
                f"The {attr} attribute MUST have a value - TR pag. 9",
                **error_kwargs,
            )

            if attr == "Format":
                exp = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
                self._assertEqual(
                    value,
                    exp,
                    f"The {attr} attribute MUST be {exp} - TR pag. 9",
                    **error_kwargs,
                )
        return self.is_ok(f"{self.__class__.__name__}.test_Issuer")

    def test_NameIDPolicy(self):
        """Test the compliance of NameIDPolicy element"""

        e = self.doc.xpath("//AuthnRequest/NameIDPolicy")

        desc = [etree.tostring(ent).decode() for ent in e if e]
        error_kwargs = dict(description=desc) if desc else {}

        self._assertTrue(
            (len(e) == 1),
            "One NameIDPolicy element MUST be present - TR pag. 9",
            **error_kwargs,
        )

        if not e:
            return self.is_ok(f"{self.__class__.__name__}.test_AuthnRequest")
        else:
            e = e[0]

        self._assertTrue(
            ("AllowCreate" not in e.attrib),
            "The AllowCreate attribute MUST not be present - AV n.5 ",
            **error_kwargs,
        )

        attr = "Format"
        self._assertTrue(
            (attr in e.attrib),
            f"The {attr} attribute MUST be present - TR pag. 9",
            **error_kwargs,
        )

        value = e.get(attr)

        self._assertIsNotNone(
            value, f"The {attr} attribute MUST have a value - TR pag. 9", **error_kwargs
        )

        if attr == "Format":
            exp = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
            self._assertEqual(
                value,
                exp,
                f"The {attr} attribute MUST be {exp} - TR pag. 9",
                **error_kwargs,
            )
        return self.is_ok(f"{self.__class__.__name__}.test_NameIDPolicy")

    def test_Conditions(self):
        """Test the compliance of Conditions element"""
        e = self.doc.xpath("//AuthnRequest/Conditions")

        desc = [etree.tostring(ent).decode() for ent in e if e]
        error_kwargs = dict(description=desc) if desc else {}

        if len(e) > 1:
            self._assertEqual(
                len(1),
                1,
                "Only one Conditions element is allowed - TR pag. 9",
                **error_kwargs,
            )

        if len(e) == 1:
            e = e[0]
            for attr in ["NotBefore", "NotOnOrAfter"]:
                self._assertTrue(
                    (attr in e.attrib),
                    f"The {attr} attribute MUST be present - TR pag. 9",
                    **error_kwargs,
                )

                value = e.get(attr)

                self._assertIsNotNone(
                    value,
                    f"The {attr} attribute MUST have a value - TR pag. 9",
                    **error_kwargs,
                )

                self._assertTrue(
                    bool(constants.regex.UTC_STRING.search(value)),
                    f"The {attr} attribute MUST have avalid UTC string - TR pag. 9",
                    **error_kwargs,
                )
        return self.is_ok(f"{self.__class__.__name__}.test_Conditions")

    def test_RequestedAuthnContext(self):
        """Test the compliance of RequestedAuthnContext element"""

        e = self.doc.xpath("//AuthnRequest/RequestedAuthnContext")

        desc = [etree.tostring(ent).decode() for ent in e if e]
        error_kwargs = dict(description=desc) if desc else {}

        self._assertEqual(
            len(e),
            1,
            "Only one RequestedAuthnContext element MUST be present - TR pag. 9",
            **error_kwargs,
        )
        if e:
            e = e[0]

            attr = "Comparison"
            self._assertTrue(
                (attr in e.attrib),
                f"The {attr} attribute MUST be present - TR pag. 10",
                **error_kwargs,
            )

            value = e.get(attr)
            self._assertIsNotNone(
                value,
                f"The {attr} attribute MUST have a value - TR pag. 10",
                **error_kwargs,
            )

            allowed = ["exact", "minimum", "better", "maximum"]
            self._assertIn(
                value,
                allowed,
                "Attribute not valid - TR pag. 10",
                description=f"The {attr} attribute MUST be one of [{', '.join(allowed)}]",
            )

            acr = e.xpath("./AuthnContextClassRef")
            self._assertEqual(
                len(acr),
                1,
                "Only one AuthnContexClassRef element MUST be present - TR pag. 9",
                description=[etree.tostring(_acr).decode() for _acr in acr],
            )

            if acr:
                acr = acr[0]
                self._assertIsNotNone(
                    acr.text,
                    "The AuthnContexClassRef element MUST have a value - TR pag. 9",
                    description=etree.tostring(acr),
                )

                self._assertTrue(
                    bool(constants.SPID_LEVEL_ALL.search(acr.text)),
                    "The AuthnContextClassRef element MUST have a valid SPID level - TR pag. 9 and AV n.5",
                    description=etree.tostring(acr),
                )
        return self.is_ok(f"{self.__class__.__name__}.test_RequestedAuthnContext")

    def test_Signature(self):
        """Test the compliance of Signature element"""

        if not self.IS_HTTP_REDIRECT:
            sign = self.doc.xpath("//AuthnRequest/Signature")

            desc = [etree.tostring(ent).decode() for ent in sign if sign]
            error_kwargs = dict(description=desc) if desc else {}

            self._assertTrue(
                (len(sign) == 1),
                "The Signature element MUST be present - TR pag. 10",
                **error_kwargs,
            )

            method = sign[0].xpath("./SignedInfo/SignatureMethod")
            self._assertTrue(
                (len(method) == 1),
                "The SignatureMethod element MUST be present- TR pag. 10",
                **error_kwargs,
            )

            self._assertTrue(
                ("Algorithm" in method[0].attrib),
                "The Algorithm attribute MUST be present "
                "in SignatureMethod element - TR pag. 10",
                **error_kwargs,
            )

            alg = method[0].get("Algorithm")
            self._assertIn(
                alg,
                constants.ALLOWED_XMLDSIG_ALGS,
                "The signature algorithm MUST be valid - TR pag. 10",
                description=f"One of {', '.join(constants.ALLOWED_XMLDSIG_ALGS)}",
            )  # noqa

            method = sign[0].xpath("./SignedInfo/Reference/DigestMethod")
            self._assertTrue(
                (len(method) == 1),
                "The DigestMethod element MUST be present",
                **error_kwargs,
            )

            self._assertTrue(
                ("Algorithm" in method[0].attrib),
                "The Algorithm attribute MUST be present "
                "in DigestMethod element - TR pag. 10",
                **error_kwargs,
            )

            alg = method[0].get("Algorithm")
            self._assertIn(
                alg,
                constants.ALLOWED_DGST_ALGS,
                (
                    ("The digest algorithm MUST be one of [%s] - TR pag. 10")
                    % (", ".join(constants.ALLOWED_DGST_ALGS))
                ),
                **error_kwargs,
            )

            # save the grubbed certificate for future alanysis
            # cert = sign[0].xpath('./KeyInfo/X509Data/X509Certificate')[0]
            # dump_pem.dump_request_pem(cert, 'authn', 'signature', DATA_DIR)
        return self.is_ok(f"{self.__class__.__name__}.test_Signature")

    def test_RelayState(self):
        """Test the compliance of RelayState parameter"""
        if ("RelayState" in self.params) and self.params.get("RelayState"):
            relaystate = self.params["RelayState"]
            self._assertTrue(
                (relaystate.find("http") == -1),
                "RelayState MUST not be immediately intelligible - TR pag. 14 or pag. 15",
                description=relaystate,
            )
        else:
            self._assertTrue(
                False,
                "RelayState is missing - TR pag. 14 or pag. 15",
                description="Missing RelayState",
            )
        return self.is_ok(f"{self.__class__.__name__}.test_RelayState")

    def test_profile_saml2core(self):
        self.test_xsd()
        self.test_AuthnRequest()
        self.test_Subject()
        self.test_Issuer()
        self.test_Conditions()

    def test_profile_spid_sp(self):
        self.test_profile_saml2core()

        self.test_RelayState()
        self.test_Signature()
        self.test_xmldsig()
        self.test_AuthnRequest_SPID()
        self.test_NameIDPolicy()
        self.test_RequestedAuthnContext()
