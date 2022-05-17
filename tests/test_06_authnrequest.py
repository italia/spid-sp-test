import pytest
import re

from . import UNSIGNED_AUTHNREQ
from . import UNSIGNED_METADATA
from . import load_authnreq


def test_authnreq_spid():
    md = load_authnreq(
        metadata = UNSIGNED_METADATA,
        authn_request_url = UNSIGNED_AUTHNREQ
    )
    md.test_AuthnRequest_SPID()
    assert not md.errors


def test_authnreq_spid_noacs_url():
    _authn_req = re.sub(
        r'AssertionConsumerServiceURL=".*"', "", UNSIGNED_AUTHNREQ.decode()
    )
    md = load_authnreq(
        metadata = UNSIGNED_METADATA,
        authn_request_url = _authn_req.encode()
    )
    md.test_AuthnRequest_SPID()
    _errors = [err['test'] for err in md.errors]
    assert 'The AssertionConsumerServiceURL attribute MUST be present' in _errors
    assert 'The AssertionConsumerServiceURL attribute MUST be equal to an AssertionConsumerService Location' in _errors
    assert 'The AttributeConsumingServiceIndex attribute MUST be present' in _errors


def test_authnreq_spid_noacs_double_acs_url():
    _authn_req = re.sub(
        r'AttributeConsumingServiceIndex="0"',
        'AttributeConsumingServiceIndex="0" AssertionConsumerServiceURL="https://that-thing.net"',
        UNSIGNED_AUTHNREQ.decode()
    )
    with pytest.raises(Exception):
        md = load_authnreq(
            metadata = UNSIGNED_METADATA,
            authn_request_url = _authn_req.encode()
        )

def test_authnreq_spid_noacs_double_acs_faulty():
    _authn_req = re.sub(
        r'AssertionConsumerServiceURL=".*"',
        'AttributeConsumingServiceIndex="0" AssertionConsumerServiceURL=""',
        UNSIGNED_AUTHNREQ.decode()
    )
    md = load_authnreq(
        metadata = UNSIGNED_METADATA,
        authn_request_url = _authn_req.encode()
    )
    md.test_AuthnRequest_SPID()
    _errors = [err['test'] for err in md.errors]
    assert 'The AssertionConsumerServiceURL attribute MUST have a value' in _errors
    assert 'The AssertionConsumerServiceURL attribute MUST be equal to an AssertionConsumerService Location' in _errors
