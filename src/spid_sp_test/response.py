import base64
import datetime
import importlib
import json
import logging
import random
import requests
import os
import sys
import string


from copy import deepcopy
from jinja2 import Environment, Markup, FileSystemLoader, Template, select_autoescape
from lxml import etree

from saml2.sigver import CryptoBackendXmlSec1, XmlsecError
from spid_sp_test import BASE_DIR, AbstractSpidCheck
from spid_sp_test.authn_request import get_authn_request
from spid_sp_test.idp.settings import SAML2_IDP_CONFIG
from spid_sp_test.responses import settings
from spid_sp_test.utils import del_ns
from tempfile import NamedTemporaryFile

from .constants import NOSESINDEX_ACRS
from .utils import get_xmlsec1_bin, html_absolute_paths
from .utils import load_plugin

logger = logging.getLogger(__name__)


def stupid_rnd_string(N=32):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(N))


def saml_rnd_id():
    return (
        f"_{stupid_rnd_string(8)}"
        f"-{stupid_rnd_string(4)}"
        f"-{stupid_rnd_string(4)}"
        f"-{stupid_rnd_string(4)}"
        f"-{stupid_rnd_string(12)}"
    )


class SpidSpResponse(object):
    def __init__(
        self,
        conf=None,
        response_attrs={},
        authnreq_attrs={},
        attributes={},
        template_path="./templates",
        status_codes=None,
    ):

        try:
            self.conf = deepcopy(
                settings.RESPONSE_TESTS[conf] or settings.RESPONSE_TESTS["1"]
            )
        except KeyError:
            raise Exception(f"Test {conf} doesn't exists")

        # rewrite, eg: response_mods
        if status_codes:
            self.conf["status_codes"] = self.status_codes

        self.attributes = attributes
        self.authnreq_attrs = authnreq_attrs
        self.response_attrs = response_attrs

        self.loader = Environment(
            loader=FileSystemLoader(searchpath=template_path),
            autoescape=select_autoescape(["xml"]),
        )
        self.template_name = self.conf.get("path", "base.xml")
        self.private_key = self.conf.get("sign_credentials", {}).get("privateKey")

    def render_attributes(self, attributes={}):
        """
        fill values to be released as identity attributes
        """
        attr_rendr_list = []
        attrs = attributes or self.attributes or settings.ATTRIBUTES

        for k, v in attrs.items():
            template = Template(settings.ATTRIBUTE_TMPL)
            attr_type = settings.ATTRIBUTES_TYPES.get(k, "string")
            attr_rendr = template.render(name=k, value=v, type=attr_type)
            attr_rendr_list.append(attr_rendr)
        return Markup("\n".join(attr_rendr_list))

    def render(self, user_attrs: dict = {}, data: dict = {}):
        template = self.loader.get_template(self.template_name)
        data = data or self.response_attrs
        data["Attributes"] = self.render_attributes(attributes=user_attrs)
        result = template.render(**data)
        logger.debug(f"Rendering response template {template}: {result}")
        return result

    def __str__(self):
        return self.conf


class SpidSpResponseCheck(AbstractSpidCheck):
    template_path = f"{BASE_DIR}/responses/templates/"

    def __init__(self, *args, **kwargs):
        super(SpidSpResponseCheck, self).__init__(*args, **kwargs)
        self.category = "response"

        self.template_path = kwargs.get("template_path", self.template_path)
        self.metadata_etree = kwargs.get("metadata_etree")

        self.authn_request_url = kwargs.get("authn_request_url")
        self.authn_request_data = {}

        # signing
        self.crypto_backend = CryptoBackendXmlSec1(
            xmlsec_binary=kwargs.get("xmlsec_binary") or get_xmlsec1_bin()
        )
        self.private_key_fpath = SAML2_IDP_CONFIG["key_file"]

        # tests
        self.tests = {}
        for i in kwargs.get("test_jsons", []):
            with open(i[0], "r") as json_data:
                self.tests.update(json.loads(json_data.read()))
        if not self.tests:
            self.tests.update(settings.RESPONSE_TESTS)
        self.test_names = kwargs.get("test_names") or self.tests.keys()

        self.attr_json = kwargs.get("attr_json")

        self.html_path = kwargs.get("html_path")
        self.no_send_response = kwargs.get("no_send_response")
        self.kwargs = kwargs
        self.status_codes = None

        self.authn_plugin = kwargs.get("authn_plugin")
        self.requests_session = kwargs.get("requests_session")

        self.request_method = kwargs.get("request_method")
        self.request_body = kwargs.get("request_body")
        self.request_content_type = kwargs.get("request_content_type")

    def get_acr(self):
        _acr = self.authnreq_etree.xpath("//RequestedAuthnContext/AuthnContextClassRef")
        if _acr:
            return _acr[0].text

    def load_user_attributes(self):
        self.requested_attrs_raw = self.metadata_etree.xpath(
            f"//SPSSODescriptor/AttributeConsumingService[@index={self.acs_index}]"
            "/RequestedAttribute"
        )
        self.requested_attrs = [
            i.attrib["Name"] for i in self.requested_attrs_raw
        ]

        # attributes
        if self.attr_json:
            with open(self.attr_json, "r") as json_data:
                self.user_attrs = json.loads(json_data.read())
        else:
            # returns ONLY the requested attributes shown in the metadata
            # otherwise it returns all the attributes (for test purpose)
            self.user_attrs = {
                i:settings.ATTRIBUTES[i] for i in self.requested_attrs
            } or settings.ATTRIBUTES

    def do_authnrequest(self):
        self.authn_request_data = get_authn_request(
            self.authn_request_url,
            authn_plugin=self.authn_plugin,
            requests_session=self.requests_session,
            request_method=self.request_method,
            request_body=self.request_body,
            request_content_type=self.request_content_type,
        )
        self.authnreq_etree = etree.fromstring(
            self.authn_request_data["SAMLRequest_xml"]
        )
        del_ns(self.authnreq_etree)

        self.issuer = self.kwargs.get("issuer", SAML2_IDP_CONFIG["entityid"])
        self.authnreq_attrs = self.authnreq_etree.xpath("/AuthnRequest")[0].attrib
        self.authnreq_issuer = self.authnreq_etree.xpath("/AuthnRequest/Issuer")[
            0
        ].attrib["NameQualifier"]

        now = datetime.datetime.utcnow()

        self.acs_index = self.authnreq_attrs.get('AttributeConsumingServiceIndex')
        self.acs_url = self.metadata_etree.xpath(
            f"//SPSSODescriptor/AssertionConsumerService[@index={self.acs_index}]"
        )[0].attrib["Location"]
        self.acr = self.get_acr()

        if self.acr in NOSESINDEX_ACRS:
            _session_index = None
        else:
            _session_index = saml_rnd_id()
        self.response_attrs = {
            "ResponseID": saml_rnd_id(),
            "AuthnRequestID": self.authnreq_attrs["ID"],
            "IssueInstant": self.authnreq_attrs["IssueInstant"],
            "NotOnOrAfter": (now + datetime.timedelta(minutes=5)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "AssertionConsumerURL": self.authnreq_attrs.get(
                "AssertionConsumerURL", self.acs_url
            ),
            "NameIDNameQualifier": settings.DEFAULT_RESPONSE["NameIDNameQualifier"],
            "NameID": "that-transient-opaque-value",
            "AssertionID": saml_rnd_id(),
            "AuthnIstant": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "SessionIndex": _session_index,
            "Issuer": self.issuer,
            "Audience": self.authnreq_issuer,
            "AuthnContextClassRef": (
                self.acr or settings.DEFAULT_RESPONSE["AuthnContextClassRef"]
            ),
            "IssueInstantMillis": now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "sign_response": settings.DEFAULT_RESPONSE["sign_response"],
            "sign_assertion": settings.DEFAULT_RESPONSE["sign_assertion"],
        }
        self.relay_state = self.kwargs.get("relay_state")

    def sign(self, xmlstr, assertion=True, response=True, key_file=None):
        """
        Sign an XML statement.
        """
        signature_node = Template(settings.SIGNATURE_TMPL)
        key_file = key_file or self.private_key_fpath
        com_list = [self.crypto_backend.xmlsec, "--sign", "--privkey-pem", key_file]

        asser_placeholder = "<!-- Assertion Signature here -->"
        if assertion and asser_placeholder in xmlstr:
            assertion_id = self.response_attrs.get("AssertionID")
            if assertion_id:
                ref_data = {"ReferenceURI": f"#{assertion_id}"}
            else:
                ref_data = {}
            value = signature_node.render(**ref_data)
            xmlstr = xmlstr.replace(asser_placeholder, value)

            with NamedTemporaryFile(suffix=".xml") as ntf:
                ntf.write(xmlstr.encode())
                ntf.seek(0)
                _com_list = [
                    "--id-attr:ID",
                    "urn:oasis:names:tc:SAML:2.0:assertion:Assertion",
                    # '--node-id',
                    # f'{self.response_attrs["AssertionID"]}'
                ]
                _com = com_list + _com_list
                p_out, p_err, xmlstr = self.crypto_backend._run_xmlsec(_com, [ntf.name])
                xmlstr = xmlstr.decode()

        sign_placeholder = "<!-- Response Signature here -->"
        if response and sign_placeholder in xmlstr:
            response_id = self.response_attrs.get("ResponseID")
            if response_id:
                ref_data = {"ReferenceURI": f"#{response_id}"}
            else:
                ref_data = {}
            value = signature_node.render(**ref_data)
            xmlstr = xmlstr.replace(sign_placeholder, value)
            with NamedTemporaryFile(suffix=".xml") as ntf:
                ntf.write(xmlstr.encode())
                ntf.seek(0)
                _com_list = [
                    "--id-attr:ID",
                    "urn:oasis:names:tc:SAML:2.0:protocol:Response",
                    # '--node-id',
                    # f'{self.response_attrs["ResponseID"]}'
                ]
                _com = com_list + _com_list
                p_out, p_err, xmlstr = self.crypto_backend._run_xmlsec(_com, [ntf.name])
                xmlstr = xmlstr.decode()

        return xmlstr.decode() if isinstance(xmlstr, bytes) else xmlstr

    def load_test(self, test_name=None, attributes={}, response_attrs={}):
        spid_response = SpidSpResponse(
            test_name,
            authnreq_attrs=self.authnreq_attrs,
            attributes=attributes,
            response_attrs=response_attrs or self.response_attrs,
            template_path=self.template_path,
            status_codes=self.status_codes,
        )
        conf = settings.RESPONSE_TESTS[test_name]
        if conf.get("response"):
            for k, v in conf["response"].items():
                logger.debug(f"Test {test_name}: overwriting {k} with {v}")
                spid_response.response_attrs[k] = v

        # response dinamyc mods and rewrites (plugins)
        if conf.get("response_mods"):
            for mod_func in conf["response_mods"]:
                n1, _, n2 = mod_func.rpartition(".")
                module = importlib.import_module(n1)
                func = getattr(module, n2)
                func(self, spid_response)

        return spid_response

    def check_response(self, res, msg: str, attendeds=[], test_id=""):
        if res.status_code in attendeds:
            status = True
        else:
            status = False
        status_code = f"[http status_code: {res.status_code}]"
        self._assertTrue(
            status,
            msg,
            method=f"{self.__class__.__name__}.check_response",
            description=status_code,
            references=[],
            test_id=test_id,
        )
        return status, status_code

    def dump_html_response(self, fname, description, result, content):
        try:
            content = html_absolute_paths(content, self.acs_url)
        except Exception as e:
            logger.critical(
                f"Something went wrong making absolute links in html content: {e}"
            )

        content = content.decode() if isinstance(content, bytes) else content
        head = f"<!-- {description} -->\n\n" f"<!-- {result} -->\n\n"
        os.makedirs(self.html_path, exist_ok=True)
        with open(f"{self.html_path}/{fname}.html", "w") as f:
            f.write(head)
            f.write(content)

    def send_response(self, xmlstr):
        data = {
            "RelayState": self.authn_request_data.get("RelayState", "/"),
            "SAMLResponse": base64.b64encode(xmlstr.encode()),
        }
        url = self.authnreq_attrs.get("AssertionConsumerURL", self.acs_url)
        ua = self.requests_session  # self.authn_request_data["requests_session"]
        if self.authn_plugin:
            func = load_plugin(self.authn_plugin)
            res = func(ua, self.authn_request_url).response(url, data)
        else:
            res = ua.post(url, data=data, allow_redirects=True)
        msg = f"Response http status code [{res.status_code}]: {res.content.decode()}"
        self.logger.debug(msg)
        return res

    def test_profile_spid_sp(self):
        for i in self.test_names:
            self.do_authnrequest()
            self.load_user_attributes()
            response_obj = self.load_test(test_name=i)
            test_display_desc = response_obj.conf["description"]
            msg = f'Response [{i}] "{test_display_desc}"'
            xmlstr = response_obj.render(user_attrs=self.user_attrs)
            try:
                result = self.sign(xmlstr, key_file=response_obj.private_key)
            except XmlsecError as e:
                logger.error(f"{msg}: Exception during xmlsec signature ({e})")
                logger.debug("{xmlstr}")
                break

            logger.debug(result)

            if not self.no_send_response and not self.authn_request_data.get(
                "requests_session"
            ):
                logger.critical(
                    "Responsens will be not sent. "
                    "You MUST adopt a http authn url to send "
                    "responses interactively."
                )
                sys.exit(1)

            if self.no_send_response:
                print(f"<!-- {test_display_desc} -->\n{result}")

            else:
                res = self.send_response(result)
                status, status_msg = self.check_response(
                    res,
                    msg=f"Test [{i}] {test_display_desc}",
                    attendeds=response_obj.conf["status_codes"],
                    test_id=i,
                )
                if self.html_path:
                    self.dump_html_response(
                        f"{i}_{status}",
                        response_obj.conf["description"],
                        result,
                        res.content.decode(),
                    )

            # reset session
            self.requests_session = requests.Session()

        self.is_ok(f"{self.__class__.__name__}")
