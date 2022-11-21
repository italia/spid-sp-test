import base64
import binascii
import copy
import logging
import os
import re
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
from spid_sp_test.utils import get_xmlsec1_bin

from saml2.server import Server

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
        raise SAMLRequestNotFound(f"{authn_request_str[:128]}")
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
            raise Exception(
                f"Can't detect authn request from f{authn_request_url}:"
                f"{authn_request_str[:128]}"
            )
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
        self.authn_request_url = authn_request_url
        self.production = production
        self.authn_plugin = authn_plugin
        self.request_method = request_method
        self.request_body = request_body
        self.request_content_type = request_content_type
        self.xsds_files = xsds_files or self.xsds_files
        self.xsds_files_path = xsds_files_path or f"{BASE_DIR}/xsd"
        
    def load(self):
        try:
            self.authn_request = get_authn_request(
                self.authn_request_url,
                verify_ssl=self.production,
                authn_plugin=self.authn_plugin,
                request_method=self.request_method,
                request_body=self.request_body,
                request_content_type=self.request_content_type,
            )
        except binascii.Error as exp:
            _msg = "Base64 decode of AuthnRequest MUST be correct"
            logger.critical(_msg + f": {exp}")
            _method = f"{self.__class__.__name__}.test_xmldsig-pre"
            self._assertTrue(
                False, _msg, test_id=["2.0.0"], description=exp, method=_method
            )
            self.is_ok(_method)
            raise exp

        try:
            self.authn_request_decoded = self.authn_request["SAMLRequest_xml"]
            self.authn_request_encoded = self.authn_request["SAMLRequest"]

        except KeyError:
            raise SAMLRequestNotFound(self.authn_request)

        self.relay_state = self.authn_request.get("RelayState") or ""

        try:
            self.md = etree.fromstring(self.metadata)
            del_ns(self.md)

            self.doc = etree.fromstring(self.authn_request_decoded)
            # clean up namespace (otherwise xpath doesn't work ...)
            del_ns(self.doc)
        except Exception as e:
            _method = f"Error parsing AuthnRequest: {self.authn_request_decoded}"
            self.handle_init_errors(method=_method, description=f"{e}", traceback=e)

        # binding detection
        self.IS_HTTP_REDIRECT = self.authn_request.get("Signature")
        # HTTP-REDIRECT params
        self.params = {"RelayState": self.relay_state}

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
        _method = f"{self.__class__.__name__}.test_xsd"
        _data = dict(
            test_id="",
            references=[],
            method=_method,
        )
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
            logger.info(" ".join((msg)))
        except Exception as e:
            os.chdir(_orig_pos)
            self.handle_result("error", msg, description=e, **_data)
        os.chdir(_orig_pos)

        return self.is_ok(_method)

    def test_xmldsig(self):
        certs = self.md.xpath(
            '//SPSSODescriptor/KeyDescriptor[@use="signing"]'
            "/KeyInfo/X509Data/X509Certificate/text()"
        )

        desc = certs
        _method = f"{self.__class__.__name__}.test_xmldsig"
        _data = dict(
            test_id="", references=[], method=_method, description="".join(desc)[:128]
        )
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
                    **_data,
                ),
            )
            return self.is_ok(_method)

        is_valid = False
        for cert in certs:
            cert_file = NamedTemporaryFile(suffix=".pem")

            # cert clean up ...
            cert = re.sub(r"[\n\t\s]", "", cert)

            cert_file.write(
                f"-----BEGIN CERTIFICATE-----\n{cert}\n-----END CERTIFICATE-----".encode()
            )
            cert_file.seek(0)

            pubkey_file = NamedTemporaryFile(suffix=".crt")
            x509_cert = subprocess.getoutput(
                f"openssl x509 -in {cert_file.name} -noout -pubkey"
            )
            pubkey_file.write(x509_cert.encode())
            pubkey_file.seek(0)

            if self.IS_HTTP_REDIRECT:
                _sigalg = self.authn_request.get("SigAlg", "")
                quoted_req = urllib.parse.quote_plus(self.authn_request["SAMLRequest"])
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

                dgst = _sigalg.split("-")[-1]
                signature = signature_file.name

                ver_cmd = (
                    f"openssl dgst -{dgst} "
                    f"-verify {pubkey_file.name} "
                    f"-signature {signature} {payload_file.name}"
                )
                exit_msg = subprocess.getoutput(ver_cmd)
                _data["description"] = exit_msg
                if "Verified OK" in exit_msg:
                    is_valid = True

            else:
                tmp_file = NamedTemporaryFile(suffix=".xml")
                tmp_file.write(self.authn_request_decoded)
                tmp_file.seek(0)
                
                cmd = (
                    f"{get_xmlsec1_bin()} --verify --insecure --id-attr:ID "
                    '"urn:oasis:names:tc:SAML:2.0:protocol:AuthnRequest" '
                    # f'--pubkey-cert-pem {cert_file.name} '
                    # "--X509-skip-strict-checks"
                    f"--pubkey-pem {pubkey_file.name} "
                    f"{tmp_file.name}"
                )

                logger.debug(f"Running authn request signature validation: {cmd}")
                logger.debug(f"{pubkey_file.name}:\n{x509_cert}")
                try:
                    out = subprocess.run(
                        cmd,
                        shell=True,
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )

                    if out.returncode == 0:
                        is_valid = True
                        break

                except subprocess.CalledProcessError as err:
                    lines = [msg]
                    if err.stderr:
                        stderr = "stderr: " + "\nstderr: ".join(
                            list(filter(None, err.stderr.decode().split(r"\n")))
                        )
                        lines.append(stderr)
                    if err.stdout:
                        stdout = "stdout: " + "\nstdout: ".join(
                            list(filter(None, err.stdout.decode().split(r"\n")))
                        )
                        lines.append(stdout)
                    _lines = "\n".join(lines)
                    _data["description"] = _lines
                    logger.debug(_lines)
        self._assertTrue(is_valid, "AuthnRequest Signature validation", **_data)
        return self.is_ok(_method)

    def test_AuthnRequest(self):
        """Test the compliance of AuthnRequest element"""
        req = self.doc.xpath("/AuthnRequest")
        _method = f"{self.__class__.__name__}.test_AuthnRequest"
        _data = dict(
            test_id="",
            references=["TR pag. 8"],
            method=_method,
        )

        self._assertTrue(
            (len(req) == 1), "One AuthnRequest element MUST be present", **_data
        )
        if req:
            req = req[0]
        else:
            return self.is_ok(_method)

        for attr in ("ID", "Version", "IssueInstant", "Destination"):
            self._assertTrue(
                (attr in req.attrib),
                f"The {attr} attribute MUST be present",
                description=attr,
                **_data,
            )

            value = req.get(attr)
            if attr == "ID":
                self._assertTrue(
                    value,
                    f"The {attr} attribute MUST have a value",
                    description=value,
                    **_data,
                )

            if attr == "Version":
                exp = "2.0"
                self._assertTrue(
                    value == exp,
                    f"The {attr} attribute MUST be {exp}",
                    description=value,
                    **_data,
                )

            if attr == "IssueInstant":
                self._assertTrue(
                    value,
                    f"The {attr} attribute MUST have a value",
                    description=value,
                    **_data,
                )
                self._assertTrue(
                    bool(constants.UTC_REGEXP.search(value)),
                    f"The {attr} attribute MUST be a valid UTC string",
                    description=value,
                    **_data,
                )

            if attr == "Destination":
                self._assertTrue(
                    value,
                    f"The {attr} attribute MUST have a value",
                    description=value,
                    **_data,
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
                    "which the request has been sent but can also be the EntityID of IdP (Av. SPID n.11)",
                    description=f"{value} not in {allowed_destinations}",
                    **_data,
                )

                if self.production:
                    self._assertIsValidHttpsUrl(
                        value,
                        f"The {attr} attribute MUST be a valid HTTPS url",
                        description=value,
                        **_data,
                    )
                    self._assertHttpUrlWithoutPort(
                        value,
                        'The entityID attribute MUST not contains any custom tcp ports, eg: ":8000"',
                        description=value,
                        **_data,
                    )

        self._assertTrue(
            ("IsPassive" not in req.attrib),
            "The IsPassive attribute MUST not be present - TR pag. 9 ",
            **_data,
        )
        return self.is_ok(_method)

    def test_AuthnRequest_SPID(self):
        """Test the compliance of AuthnRequest element"""
        req = self.doc.xpath("/AuthnRequest")[0]
        _method = f"{self.__class__.__name__}.test_AuthnRequest_SPID"
        _data = dict(
            test_id="",
            references=["TR pag. 8"],
            method=_method,
        )

        acr = req.xpath("//RequestedAuthnContext/AuthnContextClassRef")
        acr_desc = [etree.tostring(_acr).decode() for _acr in acr]

        if acr:
            level = acr[0].text
            if bool(constants.SPID_LEVEL_23.search(level)):
                self._assertTrue(
                    ("ForceAuthn" in req.attrib),
                    "The ForceAuthn attribute MUST be present if SPID level > 1",
                    description=acr_desc,
                    **_data,
                )
                value = req.get("ForceAuthn")
                if value:
                    self._assertTrue(
                        (value.lower() in constants.BOOLEAN_TRUE),
                        "The ForceAuthn attribute MUST be true or 1 - TR pag. 8 ",
                        description=value,
                        **_data,
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
                f"The {attr} attribute MUST be equal to an AssertionConsumerService index",
                description=acss_desc,
                **_data,
            )

            self._assertTrue(
                value,
                f"The {attr} attribute MUST have a value",
                description=value,
                **_data,
            )
            self._assertTrue(
                int(value) >= 0,
                f"The {attr} attribute MUST be >= 0",
                description=value,
                **_data,
            )

        else:
            availableassertionlocations = []

            for acs in acss:
                location = acs.get("Location")
                availableassertionlocations.append(location)

            for attr in ["AssertionConsumerServiceURL", "ProtocolBinding"]:
                self._assertTrue(
                    (attr in req.attrib),
                    f"The {attr} attribute MUST be present",
                    description=req.attrib,
                    **_data,
                )

                value = req.get(attr)
                self._assertTrue(
                    value,
                    f"The {attr} attribute MUST have a value",
                    description=value,
                    **_data,
                )

                if attr == "AssertionConsumerServiceURL":
                    if self.production:
                        self._assertIsValidHttpsUrl(
                            value,
                            f"The {attr} attribute MUST be a valid HTTPS url",
                            description=value,
                            **_data,
                        )
                        self._assertHttpUrlWithoutPort(
                            value,
                            'The entityID attribute MUST not contains any custom tcp ports, eg: ":8000"',
                            description=value,
                            **_data,
                        )
                    self._assertTrue(
                        value in availableassertionlocations,
                        f"The {attr} attribute MUST be equal to an AssertionConsumerService Location",
                        description=value,
                        **_data,
                    )

                if attr == "ProtocolBinding":
                    exp = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                    self._assertTrue(
                        value == exp,
                        f"The {attr} attribute MUST be {exp}",
                        description=value,
                        **_data,
                    )

        attr = "AttributeConsumingServiceIndex"
        if attr not in req.attrib:
            self._assertTrue(
                (attr in req.attrib),
                f"The {attr} attribute MUST be present",
                description=req.attrib,
                **_data,
            )
        else:
            availableattributeindexes = []

            acss = self.md.xpath(
                "//EntityDescriptor/SPSSODescriptor/AttributeConsumingService"
            )
            for acs in acss:
                index = acs.get("index")
                availableattributeindexes.append(index)

            value = req.get(attr)
            self._assertTrue(
                value,
                f"The {attr} attribute MUST have a value",
                description=value,
                **_data,
            )
            self._assertTrue(
                int(value) >= 0,
                f"The {attr} attribute MUST be >= 0",
                description=value,
                **_data,
            )
            self._assertTrue(
                value in availableattributeindexes,
                f"The {attr} attribute MUST be equal to an AttributeConsumingService index",
                description=value,
                **_data,
            )
        return self.is_ok(_method)

    def test_Subject(self):
        """Test the compliance of Subject element"""

        subj = self.doc.xpath("//AuthnRequest/Subject")

        desc = [etree.tostring(ent).decode() for ent in subj if subj]
        _method = f"{self.__class__.__name__}.test_Subject"
        _data = dict(
            test_id="",
            references=["TR pag. 9"],
            method=_method,
            description="".join(desc)[:128],
        )

        if len(subj) > 1:
            self._assertTrue(
                len(subj) == 1,
                "Only one Subject element can be present",
                description=subj,
                **_data,
            )
        # Not shure that this must be checked :)
        # elif len(subj) < 1:
        # self._assertTrue(
        # False,
        # "The Subject element MUST be present",
        # **_data,
        # )
        elif len(subj) == 1:
            subj = subj[0]
            name_id = subj.xpath("./NameID")
            self._assertTrue(
                len(name_id) == 1,
                "One NameID element in Subject element MUST be present",
                description=name_id,
                **_data,
            )
            name_id = name_id[0]
            for attr in ["Format", "NameQualifier"]:
                self._assertTrue(
                    (attr in name_id.attrib),
                    f"The {attr} attribute MUST be present",
                    description=name_id.attrib,
                    **_data,
                )

                value = name_id.get(attr)
                self._assertTrue(
                    value,
                    f"The {attr} attribute MUST have a value",
                    description=value,
                    **_data,
                )

                if attr == "Format":
                    exp = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
                    self._assertTrue(
                        value == exp,
                        f"The {attr} attribute MUST be {exp}",
                        description=value,
                        **_data,
                    )
        return self.is_ok(_method)

    def test_Issuer(self):
        """Test the compliance of Issuer element"""
        e = self.doc.xpath("//AuthnRequest/Issuer")

        desc = [etree.tostring(ent).decode() for ent in e if e]
        _method = f"{self.__class__.__name__}.test_Issuer"
        _data = dict(
            test_id="",
            references=["TR pag. 9"],
            method=_method,
            description="".join(desc)[:128],
        )

        self._assertTrue(
            (len(e) == 1),
            "One Issuer element MUST be present",
            **_data,
        )

        if not e:
            self._assertTrue(
                e,
                "The Issuer element MUST be present",
                **_data,
            )
            return self.is_ok(_method)
        else:
            e = e[0]

        self._assertTrue(e.text, "The Issuer element MUST have a value", **_data)

        entitydescriptor = self.md.xpath("//EntityDescriptor")
        entityid = entitydescriptor[0].get("entityID")
        _data.pop("description")
        self._assertTrue(
            e.text == entityid,
            "The Issuer's value MUST be equal to entityID",
            description=e.text,
            **_data,
        )

        for attr in ["Format", "NameQualifier"]:
            self._assertTrue(
                (attr in e.attrib),
                f"The {attr} attribute MUST be present",
                description=e.attrib,
                **_data,
            )

            value = e.get(attr)

            self._assertTrue(
                value,
                f"The {attr} attribute MUST have a value",
                description=value,
                **_data,
            )

            if attr == "Format":
                exp = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
                self._assertTrue(
                    value == exp,
                    f"The {attr} attribute MUST be {exp}",
                    description=value,
                    **_data,
                )
        return self.is_ok(_method)

    def test_NameIDPolicy(self):
        """Test the compliance of NameIDPolicy element"""

        e = self.doc.xpath("//AuthnRequest/NameIDPolicy")

        desc = [etree.tostring(ent).decode() for ent in e if e]
        _method = f"{self.__class__.__name__}.test_NameIDPolicy"
        _data = dict(
            test_id="",
            references=["TR pag. 9"],
            method=_method,
            description="".join(desc)[:128],
        )

        self._assertTrue(
            (len(e) == 1),
            "One NameIDPolicy element MUST be present",
            **_data,
        )

        if not e:
            self._assertTrue(
                e,
                "The NameIDPolicy element MUST be present",
                **_data,
            )
            return self.is_ok(_method)
        else:
            e = e[0]

        _data.pop("description")
        attr = "Format"
        self._assertTrue(
            (attr in e.attrib),
            f"The {attr} attribute MUST be present",
            description=e.attrib,
            **_data,
        )

        value = e.get(attr)
        self._assertTrue(
            value,
            f"The {attr} attribute MUST have a value",
            description=value,
            **_data,
        )

        if attr == "Format":
            exp = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
            self._assertTrue(
                value == exp,
                f"The {attr} attribute MUST be {exp}",
                description=value,
                **_data,
            )

        _data["references"] = ["AV n.5"]
        self._assertTrue(
            ("AllowCreate" not in e.attrib),
            "The AllowCreate attribute MUST not be present",
            description=value,
            **_data,
        )
        return self.is_ok(_method)

    def test_Conditions(self):
        """Test the compliance of Conditions element"""
        e = self.doc.xpath("//AuthnRequest/Conditions")

        desc = [etree.tostring(ent).decode() for ent in e if e]
        _method = f"{self.__class__.__name__}.test_Conditions"
        _data = dict(
            test_id="",
            references=["TR pag. 9"],
            method=_method,
            description="".join(desc)[:128],
        )

        if len(e) > 1:
            self._assertTrue(
                len(1) == 1,
                "Only one Conditions element is allowed",
                **_data,
            )
        # Not shure that this must be checked :)
        # elif len(e) < 1:
        # self._assertTrue(
        # e,
        # "The Conditions element MUST be present",
        # **_data,
        # )
        # return self.is_ok(_method)

        elif len(e) == 1:
            e = e[0]
            _data["description"] = e
            for attr in ["NotBefore", "NotOnOrAfter"]:
                self._assertTrue(
                    (attr in e.attrib),
                    f"The {attr} attribute MUST be present",
                    **_data,
                )
                value = e.get(attr)
                _data["description"] = value
                self._assertTrue(
                    value,
                    f"The {attr} attribute MUST have a value",
                    **_data,
                )
                self._assertTrue(
                    bool(constants.UTC_REGEXP.search(value)),
                    f"The {attr} attribute MUST have avalid UTC string",
                    **_data,
                )
        return self.is_ok(_method)

    def test_RequestedAuthnContext(self):
        """Test the compliance of RequestedAuthnContext element"""

        e = self.doc.xpath("//AuthnRequest/RequestedAuthnContext")
        _method = f"{self.__class__.__name__}.test_RequestedAuthnContext"
        _data = dict(
            test_id="",
            references=["TR pag. 9", "TR pag. 10"],
            method=_method,
        )

        self._assertTrue(
            len(e) == 1,
            "Only one RequestedAuthnContext element MUST be present",
            description=[etree.tostring(_val).decode() for _val in e],
            **_data,
        )
        if e:
            e = e[0]
            attr = "Comparison"
            self._assertTrue(
                (attr in e.attrib),
                f"The {attr} attribute MUST be present",
                description=e.attrib,
                **_data,
            )

            value = e.get(attr)
            self._assertTrue(
                value,
                f"The {attr} attribute MUST have a value",
                description=value,
                **_data,
            )

            allowed = ["exact", "minimum", "better", "maximum"]
            self._assertTrue(
                value in allowed,
                "Attribute not valid",
                description=f"The {attr} attribute MUST be one of [{', '.join(allowed)}]",
                **_data,
            )

            acr = e.xpath("./AuthnContextClassRef")
            self._assertTrue(
                len(acr) == 1,
                "Only one AuthnContexClassRef element MUST be present",
                description=[etree.tostring(_acr).decode() for _acr in acr],
                **_data,
            )

            if acr:
                acr = acr[0]
                self._assertTrue(
                    acr.text,
                    "The AuthnContexClassRef element MUST have a value",
                    description=etree.tostring(acr),
                    **_data,
                )

                self._assertTrue(
                    bool(constants.SPID_LEVEL_ALL.search(acr.text)),
                    "The AuthnContextClassRef element MUST have a valid SPID level",
                    description=etree.tostring(acr),
                    **_data,
                )
        return self.is_ok(_method)

    def test_Signature(self):
        """Test the compliance of Signature element"""
        _method = f"{self.__class__.__name__}.test_Signature"
        _data = dict(
            test_id="",
            references=["TR pag. 10"],
            method=_method,
        )
        if not self.IS_HTTP_REDIRECT:
            sign = self.doc.xpath("//AuthnRequest/Signature")
            # desc = [etree.tostring(ent).decode() for ent in sign if sign]

            self._assertTrue(
                (len(sign) == 1),
                "The Signature element MUST be present",
                **_data,
            )

            if sign:
                method = sign[0].xpath("./SignedInfo/SignatureMethod")
                self._assertTrue(
                    (len(method) == 1),
                    "The SignatureMethod element MUST be present",
                    **_data,
                )

                self._assertTrue(
                    ("Algorithm" in method[0].attrib),
                    "The Algorithm attribute MUST be present "
                    "in SignatureMethod element",
                    **_data,
                )

                alg = method[0].get("Algorithm")
                self._assertTrue(
                    alg in constants.ALLOWED_XMLDSIG_ALGS,
                    "The signature algorithm MUST be valid",
                    description=f"One of {', '.join(constants.ALLOWED_XMLDSIG_ALGS)}",
                    **_data,
                )  # noqa

                method = sign[0].xpath("./SignedInfo/Reference/DigestMethod")
                self._assertTrue(
                    (len(method) == 1),
                    "The DigestMethod element MUST be present",
                    **_data,
                )

                self._assertTrue(
                    ("Algorithm" in method[0].attrib),
                    "The Algorithm attribute MUST be present "
                    "in DigestMethod element",
                    **_data,
                )

                alg = method[0].get("Algorithm")
                self._assertTrue(
                    alg in constants.ALLOWED_DGST_ALGS,
                    (
                        ("The digest algorithm MUST be one of [%s]")
                        % (", ".join(constants.ALLOWED_DGST_ALGS))
                    ),
                    **_data,
                )

            # save the grubbed certificate for future analysis
            # cert = sign[0].xpath('./KeyInfo/X509Data/X509Certificate')[0]
            # dump_pem.dump_request_pem(cert, 'authn', 'signature', DATA_DIR)
        return self.is_ok(_method)

    def test_RelayState(self):
        """Test the compliance of RelayState parameter"""
        _method = f"{self.__class__.__name__}.test_RelayState"
        _data = dict(
            test_id="",
            references=["TR pag. 14", "TR pag. 15"],
            method=_method,
        )
        if ("RelayState" in self.params) and self.params.get("RelayState"):
            relaystate = self.params["RelayState"]
            self._assertTrue(
                (relaystate.find("http") == -1),
                "RelayState MUST not be immediately intelligible",
                description=relaystate,
                **_data,
            )
        else:
            self._assertTrue(
                False,
                "RelayState is missing",
                description="Missing RelayState",
            )
        return self.is_ok(_method)

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
