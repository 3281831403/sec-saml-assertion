from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from xml.dom import minidom

from engine.sso.assertion import (
    assertion_batch,
    canonicalize,
    check_audience,
    check_conditions,
    check_subject,
    replay_guard,
    signed_nodes,
    verify_signature,
)


NOW = datetime(2026, 11, 19, 12, 0, 0, tzinfo=timezone.utc)
KEY = b"saml-exercise-signing-key"
SAML_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion"
DS_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#"
SAML_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
OTHER_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"


def iso(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_document(
    assertion_id="_a1",
    subject="alice",
    audience="https://sp.example",
    not_before=None,
    not_on_or_after=None,
    issue_instant=None,
    signature_scope="full",
    key=KEY,
):
    not_before = not_before or (NOW - timedelta(minutes=1))
    not_on_or_after = not_on_or_after or (NOW + timedelta(minutes=10))
    issue_instant = issue_instant or (NOW - timedelta(minutes=1))
    xml = (
        f'<env:Envelope xmlns:env="urn:test:envelope" '
        f'xmlns:saml="{SAML_NAMESPACE}" xmlns:ds="{DS_NAMESPACE}">'
        f'<saml:Assertion ID="{assertion_id}" IssueInstant="{iso(issue_instant)}">'
        f'<saml:Issuer>https://idp.example</saml:Issuer>'
        f'<saml:Subject><saml:NameID Format="{SAML_FORMAT}">{subject}</saml:NameID>'
        f"</saml:Subject>"
        f'<saml:Conditions NotBefore="{iso(not_before)}" '
        f'NotOnOrAfter="{iso(not_on_or_after)}">'
        f"<saml:AudienceRestriction>"
        f"<saml:Audience>{audience}</saml:Audience>"
        f"</saml:AudienceRestriction>"
        f"</saml:Conditions>"
        f"</saml:Assertion>"
        f"<ds:Signature>"
        f'<ds:Reference URI="#{assertion_id}"></ds:Reference>'
        f"<ds:SignatureValue></ds:SignatureValue>"
        f"</ds:Signature>"
        f"</env:Envelope>"
    )
    document = minidom.parseString(xml)
    assertion = document.getElementsByTagName("saml:Assertion")[0]
    subject_node = document.getElementsByTagName("saml:Subject")[0]
    target = assertion if signature_scope == "full" else subject_node
    payload = canonicalize(target)
    signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
    signature_value = document.getElementsByTagName("ds:SignatureValue")[0]
    signature_value.appendChild(document.createTextNode(signature))
    return document


def valid_assertion_data():
    return {
        "id": "_a1",
        "issuer": "https://idp.example",
        "subject": {"value": "alice", "format": SAML_FORMAT},
        "audiences": ["https://sp.example"],
        "conditions": {
            "not_before": NOW - timedelta(minutes=1),
            "not_on_or_after": NOW + timedelta(minutes=10),
            "issue_instant": NOW - timedelta(minutes=1),
            "audiences": ["https://sp.example"],
        },
    }


def batch_policy():
    return {
        "skew": timedelta(0),
        "ttl": timedelta(minutes=5),
        "replay_store": {},
    }


def batch_request(name, document, subject):
    return {
        "name": name,
        "document": document,
        "key": KEY,
        "request": {
            "audience": "https://sp.example",
            "subject": {"value": subject, "format": SAML_FORMAT},
        },
    }


def test_canonicalize_namespace_declaration_order_is_stable():
    first = minidom.parseString(
        '<r:root xmlns:r="urn:r" xmlns:z="urn:z" xmlns:a="urn:a" id="1">'
        "<r:item/></r:root>"
    ).documentElement
    second = minidom.parseString(
        '<r:root xmlns:r="urn:r" xmlns:a="urn:a" xmlns:z="urn:z" id="1">'
        "<r:item/></r:root>"
    ).documentElement
    assert canonicalize(first) == canonicalize(second)


def test_canonicalize_empty_element_is_self_closing():
    node = minidom.parseString('<empty attr="1"/>').documentElement
    assert canonicalize(node) == b'<empty attr="1"/>'


def test_signed_nodes_rejects_duplicate_ids():
    document = minidom.parseString(
        f'<env:Envelope xmlns:env="urn:test:envelope" '
        f'xmlns:saml="{SAML_NAMESPACE}" xmlns:ds="{DS_NAMESPACE}">'
        f'<saml:Assertion ID="_dup"><saml:Issuer>one</saml:Issuer></saml:Assertion>'
        f'<saml:Assertion ID="_dup"><saml:Issuer>two</saml:Issuer></saml:Assertion>'
        f'<ds:Signature><ds:Reference URI="#_dup"></ds:Reference></ds:Signature>'
        f"</env:Envelope>"
    )
    assert signed_nodes(document) == []


def test_signature_rejects_incomplete_coverage():
    document = build_document(signature_scope="subject")
    assert verify_signature(document, KEY) is False


def test_conditions_skew_is_applied_once():
    assertion = {
        "conditions": {
            "not_before": NOW,
            "not_on_or_after": NOW + timedelta(minutes=10),
            "issue_instant": NOW - timedelta(minutes=1),
        }
    }
    result = check_conditions(
        assertion, NOW + timedelta(minutes=12), timedelta(minutes=5)
    )
    assert result["valid"] is False


def test_conditions_reject_future_issue_instant():
    assertion = {
        "conditions": {
            "not_before": NOW - timedelta(minutes=10),
            "not_on_or_after": NOW + timedelta(minutes=10),
            "issue_instant": NOW + timedelta(minutes=5),
        }
    }
    result = check_conditions(assertion, NOW, timedelta(0))
    assert result["valid"] is False


def test_audience_requires_exact_match():
    assert check_audience(
        {"audiences": ["https://sp.example"]}, "https://sp.example"
    ) is True
    assert check_audience(
        {"audiences": ["https://sp.example.attacker"]}, "https://sp.example"
    ) is False


def test_subject_same_value_different_format_is_equal():
    assertion = {"subject": {"value": "alice", "format": SAML_FORMAT}}
    request = {"subject": {"value": "alice", "format": OTHER_FORMAT}}
    assert check_subject(assertion, request) is True


def test_replay_guard_partitions_by_issuer():
    store = {}
    ttl = timedelta(minutes=5)
    assert replay_guard(store, ("https://idp-a", "_same"), NOW, ttl) is True
    assert replay_guard(store, ("https://idp-b", "_same"), NOW, ttl) is True
    assert replay_guard(store, ("https://idp-a", "_same"), NOW, ttl) is False

    store[("https://idp-c", "_expired")] = NOW - timedelta(seconds=1)
    assert replay_guard(store, ("https://idp-c", "_fresh"), NOW, ttl) is True
    assert ("https://idp-c", "_expired") not in store


def test_batch_does_not_reuse_first_canonical_bytes():
    first = build_document(assertion_id="_a1", subject="alice")
    second = build_document(assertion_id="_a2", subject="bob")
    requests = [
        batch_request("r1", first, "alice"),
        batch_request("r2", second, "bob"),
    ]
    results = assertion_batch(requests, batch_policy(), NOW)
    assert results == {"r1": True, "r2": True}


def test_valid_assertion_passes_all_checks():
    data = valid_assertion_data()
    document = build_document()
    request = {
        "audience": "https://sp.example",
        "subject": {"value": "alice", "format": SAML_FORMAT},
    }
    assert verify_signature(document, KEY) is True
    assert check_conditions(data, NOW, timedelta(0))["valid"] is True
    assert check_audience(data, "https://sp.example") is True
    assert check_subject(data, request) is True
    assert replay_guard({}, ("https://idp.example", "_a1"), NOW, timedelta(minutes=5)) is True


def test_tampered_conditions_fail_signature():
    document = build_document()
    assert verify_signature(document, KEY) is True
    conditions = document.getElementsByTagName("saml:Conditions")[0]
    conditions.setAttribute("NotOnOrAfter", iso(NOW + timedelta(minutes=30)))
    assert verify_signature(document, KEY) is False


def test_conditions_boundaries_and_expiry():
    assertion = {
        "conditions": {
            "not_before": NOW,
            "not_on_or_after": NOW + timedelta(minutes=10),
            "issue_instant": NOW - timedelta(minutes=1),
        }
    }
    skew = timedelta(minutes=5)
    assert check_conditions(assertion, NOW, skew)["valid"] is True
    assert check_conditions(assertion, NOW + timedelta(minutes=10), skew)["valid"] is True
    assert (
        check_conditions(assertion, NOW + timedelta(minutes=10, seconds=1), skew)[
            "valid"
        ]
        is False
    )
    assert check_conditions(assertion, NOW - timedelta(minutes=5), skew)["valid"] is True
    assert (
        check_conditions(assertion, NOW - timedelta(minutes=5, seconds=1), skew)[
            "valid"
        ]
        is False
    )


def test_audience_array_mismatch_rejected():
    assertion = {"audiences": ["https://sp.example.attacker"]}
    assert (
        check_audience(
            assertion, ["https://sp.example", "https://other.example"]
        )
        is False
    )


def test_batch_matches_individual_validation():
    first = build_document(assertion_id="_a1", subject="alice")
    second = build_document(assertion_id="_a2", subject="bob")
    request_first = batch_request("r1", first, "alice")
    request_second = batch_request("r2", second, "bob")

    single_first = assertion_batch([request_first], batch_policy(), NOW)
    single_second = assertion_batch([request_second], batch_policy(), NOW)
    combined = assertion_batch(
        [request_first, request_second], batch_policy(), NOW
    )
    reversed_batch = assertion_batch(
        [request_second, request_first], batch_policy(), NOW
    )

    assert single_first == {"r1": True}
    assert single_second == {"r2": True}
    assert combined == {"r1": True, "r2": True}
    assert reversed_batch == combined