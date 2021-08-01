import base64
import importlib
import lxml.objectify
import os
import re
import subprocess
import urllib
import zlib

from lxml import etree, html


def del_ns(root):
    for elem in root.getiterator():
        if not hasattr(elem.tag, "find"):
            continue
        i = elem.tag.find("}")
        if i >= 0:
            elem.tag = elem.tag[i + 1 :]
    lxml.objectify.deannotate(root, cleanup_namespaces=True)


def parse_pem(cert):
    result = []

    #
    # sigalg
    #

    cmd = " | ".join(
        [
            "openssl x509 -in %s -noout -text" % cert,
            'sed -e "s/^\\s\\s*//g"',
            'grep "Signature Algorithm"',
            "uniq",
            'cut -d":" -f2',
            'sed -e "s/^\\s\\s*//g"',
        ]
    )

    try:
        p = subprocess.run(
            cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        value = p.stdout.decode("utf-8").replace("\n", "")
        result.append(value)
    except subprocess.CalledProcessError as err:
        print(err)
        return []

    #
    # klen
    #

    cmd = " | ".join(
        [
            "openssl x509 -in %s -noout -text" % cert,
            'sed -e "s/^\\s\\s*//g"',
            'grep "Public-Key"',
            'cut -d"(" -f2',
            'cut -d" " -f1',
        ]
    )

    try:
        p = subprocess.run(
            cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        value = p.stdout.decode("utf-8").replace("\n", "")
        result.append(value)
    except subprocess.CalledProcessError as err:
        print(err)
        return []

    #
    # alg
    #

    cmd = " | ".join(
        [
            "openssl x509 -in %s -noout -text" % cert,
            'sed -e "s/^\\s\\s*//g"',
            'grep "Public Key Algorithm"',
            'cut -d":" -f2',
            'cut -d" " -f2',
        ]
    )

    try:
        p = subprocess.run(
            cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        value = p.stdout.decode("utf-8").replace("\n", "")
        result.append(value)
    except subprocess.CalledProcessError as err:
        print(err)
        return []

    #
    # validity
    #

    cmd = " | ".join(
        [
            "openssl x509 -in %s -noout -enddate" % cert,
            'cut -d"=" -f2',
            "cut -b 1-20",
        ]
    )

    try:
        p = subprocess.run(
            cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        value = p.stdout.decode("utf-8").replace("\n", "")
        result.append(value)
    except subprocess.CalledProcessError as err:
        print(err)
        return []

    return result


def saml_from_htmlform(html_content):
    tree = html.fromstring(html_content)
    for elem in tree.xpath("//form"):
        form = elem.attrib
        inputs = elem.xpath("input")
        for i in inputs:
            if i.attrib["name"] == "SAMLRequest":
                form["SAMLRequest"] = i.attrib["value"]
            elif i.attrib["name"] == "SAMLResponse":
                form["SAMLResponse"] = i.attrib["value"]
            elif i.attrib["name"] == "RelayState":
                form["RelayState"] = i.attrib["value"]
        return form


def decode_authn_req_http_redirect(saml_req_str):
    msg = base64.b64decode(saml_req_str)
    inflated = zlib.decompress(msg, -15)
    return inflated.decode()


def get_key_pem_wrapped_unwrapped(cert):
    begin_cert = "-----BEGIN PRIVATE KEY-----\n"
    end_cert = "\n-----END PRIVATE KEY-----\n"
    unwrapped_cert = re.sub(f"{begin_cert}|{end_cert}", "", cert)
    wrapped_cert = f"{begin_cert}{unwrapped_cert}{end_cert}"
    return wrapped_cert, unwrapped_cert


def prettify_xml(msg_str) -> bytes:
    msg_etree = etree.fromstring(msg_str)
    msg = etree.tostring(
        msg_etree,
        pretty_print=True,
    )
    return msg


def get_xmlsec1_bin():
    env_bin = os.environ.get("XMLSEC1_BIN")
    which_exe = os.popen("which xmlsec1").read()
    if env_bin:
        return env_bin
    elif which_exe:
        return which_exe.splitlines()[0]
    else:
        for i in ("/usr/local/bin/xmlsec1", "/usr/bin/xmlsec1"):
            if os.access(i, os.X_OK):
                return i


def html_absolute_paths(html_content, url):
    parse = urllib.parse.urlparse(url)
    base_url = "://".join((parse.scheme, parse.netloc))
    q = html.fromstring(html_content)
    q.make_links_absolute(base_url=base_url)

    for tag in ("link", "img"):
        for i in q.xpath(f"//{tag}"):
            attr = i.attrib
            if attr.get("href"):
                first_char = attr["href"][0]
                if first_char == "/":
                    attr["href"] = f"{base_url}{attr['href']}"
                elif attr["href"][:4] == "http":
                    continue
                elif first_char != "/":
                    attr["href"] = f"{url}/{attr['href']}"

    return html.tostring(q)


def load_plugin(plugin_name):
    n1, _, n2 = plugin_name.rpartition(".")
    module = importlib.import_module(n1)
    func = getattr(module, n2)
    return func
