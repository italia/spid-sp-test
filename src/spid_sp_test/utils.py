import lxml.objectify
import subprocess


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
