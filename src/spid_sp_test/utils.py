import base64
import lxml.objectify
import re
import subprocess


from . exceptions import *


form_samlreq_regex = '[\s\n.]*name="SAMLRequest"'
form_samlreq_value_regex = 'value="(?P<value>[a-zA-Z0-9+=]*)"[\s\n.]*'


def del_ns(root):
    for elem in root.getiterator():
        if not hasattr(elem.tag, 'find'):
            continue
        i = elem.tag.find('}')
        if i >= 0:
            elem.tag = elem.tag[i+1:]
    lxml.objectify.deannotate(root, cleanup_namespaces=True)


def parse_pem(cert):
    result = []

    #
    # sigalg
    #

    cmd = ' | '.join([
        'openssl x509 -in %s -noout -text' % cert,
        'sed -e "s/^\\s\\s*//g"',
        'grep "Signature Algorithm"',
        'uniq',
        'cut -d":" -f2',
        'sed -e "s/^\\s\\s*//g"'
    ])

    try:
        p = subprocess.run(
            cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        value = p.stdout.decode('utf-8').replace('\n', '')
        result.append(value)
    except subprocess.CalledProcessError as err:
        print(err)
        return []

    #
    # klen
    #

    cmd = ' | '.join([
        'openssl x509 -in %s -noout -text' % cert,
        'sed -e "s/^\\s\\s*//g"',
        'grep "Public-Key"',
        'cut -d"(" -f2',
        'cut -d" " -f1',
    ])

    try:
        p = subprocess.run(
            cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        value = p.stdout.decode('utf-8').replace('\n', '')
        result.append(value)
    except subprocess.CalledProcessError as err:
        print(err)
        return []

    #
    # alg
    #

    cmd = ' | '.join([
        'openssl x509 -in %s -noout -text' % cert,
        'sed -e "s/^\\s\\s*//g"',
        'grep "Public Key Algorithm"',
        'cut -d":" -f2',
        'cut -d" " -f2',
    ])

    try:
        p = subprocess.run(
            cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        value = p.stdout.decode('utf-8').replace('\n', '')
        result.append(value)
    except subprocess.CalledProcessError as err:
        print(err)
        return []


    #
    # validity
    #

    cmd = ' | '.join([
        'openssl x509 -in %s -noout -enddate' % cert,
        'cut -d"=" -f2',
        'cut -b 1-20',
    ])

    try:
        p = subprocess.run(
            cmd,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        value = p.stdout.decode('utf-8').replace('\n', '')
        result.append(value)
    except subprocess.CalledProcessError as err:
        print(err)
        return []

    return result


def samlreq_from_htmlform(html_content):
    saml_request = re.search(form_samlreq_regex, html_content)
    if not saml_request:
        raise SAMLRequestNotFound()
    
    saml_req_value = re.search(form_samlreq_value_regex, html_content)
    if not saml_req_value:
        raise SAMLRequestValueNotFound()
    
    # base64 encoded
    return saml_req_value.groups()[0]


def decoded_samlreq_from_htmlform(html_content):
    base64_encoded = samlreq_from_htmlform(html_content)
    return base64.b64decode(base64_encoded)
