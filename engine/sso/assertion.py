"""SAML assertion validation primitives used by the SSO gateway.

The public surface is intentionally small: eight pure functions that operate on
minidom nodes and plain dictionaries.  The exercise tests exercise the contract
of each function independently and through the batch entry point.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from xml.dom import Node


# ---------------------------------------------------------------------------
# Canonicalization
# ---------------------------------------------------------------------------

def _local_name(name: str | None) -> str:
    """Return the local part of a possibly prefixed qualified name."""
    if not name:
        return ""
    return name.rsplit(":", 1)[-1]


def _escape_text(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\r", "&#xD;")
    )


def _escape_attr(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace('"', "&quot;")
        .replace("\t", "&#x9;")
        .replace("\n", "&#xA;")
        .replace("\r", "&#xD;")
    )


def _sorted_attributes(element) -> list:
    """All attributes (including xmlns declarations) sorted by QName.

    Namespace declarations are ordinary ``xmlns[:prefix]`` attributes in
    minidom and must participate in the same total ordering; otherwise the
    same document has two canonical byte representations depending on the
    order the declarations were parsed in.
    """
    attributes = element.attributes
    if attributes is None:
        return []
    attr_nodes = [attributes.item(i) for i in range(attributes.length)]
    return sorted(attr_nodes, key=lambda attr: attr.name)


def _serialize(node) -> str:
    if node.nodeType == Node.DOCUMENT_NODE:
        root = node.documentElement
        return _serialize(root) if root is not None else ""

    if node.nodeType != Node.ELEMENT_NODE:
        # Only elements contribute markup; the recursive walker handles the
        # other node kinds explicitly.
        return ""

    tag = node.tagName
    chunks = ["<", tag]

    for attr in _sorted_attributes(node):
        chunks.append(f' {attr.name}="{_escape_attr(attr.value)}"')

    element_children = [
        child
        for child in node.childNodes
        if child.nodeType in (Node.ELEMENT_NODE, Node.TEXT_NODE,
                              Node.CDATA_SECTION_NODE)
    ]

    if not element_children:
        # An empty element is always the self-closing form: ``<x/>`` rather
        # than ``<x></x>``.
        chunks.append("/>")
        return "".join(chunks)

    chunks.append(">")
    for child in node.childNodes:
        if child.nodeType == Node.ELEMENT_NODE:
            chunks.append(_serialize(child))
        elif child.nodeType in (Node.TEXT_NODE, Node.CDATA_SECTION_NODE):
            chunks.append(_escape_text(child.data))
        # Comments, PIs and other nodes do not participate.
    chunks.append(f"</{tag}>")
    return "".join(chunks)


def canonicalize(node) -> bytes:
    """Return the canonical byte representation of an element."""
    return _serialize(node).encode("utf-8")


# ---------------------------------------------------------------------------
# DOM helpers
# ---------------------------------------------------------------------------

def _iter_elements(node):
    """Yield every element contained in ``node`` (including node itself)."""
    if node is None:
        return
    if node.nodeType == Node.ELEMENT_NODE:
        yield node
    for child in node.childNodes or ():
        if child.nodeType == Node.ELEMENT_NODE:
            yield from _iter_elements(child)
        elif child.nodeType == Node.DOCUMENT_NODE:
            yield from _iter_elements(child)


def _find_all_local(node, local: str) -> list:
    return [el for el in _iter_elements(node) if _local_name(el.tagName) == local]


def _find_first_local(node, local: str):
    for el in _iter_elements(node):
        if _local_name(el.tagName) == local:
            return el
    return None


def _text_content(node) -> str:
    if node is None:
        return ""
    parts = []
    for child in node.childNodes or ():
        if child.nodeType in (Node.TEXT_NODE, Node.CDATA_SECTION_NODE):
            parts.append(child.data)
        elif child.nodeType == Node.ELEMENT_NODE:
            parts.append(_text_content(child))
    return "".join(parts)


def _element_id(element) -> str | None:
    for attr_name in ("ID", "Id", "id", "xml:id"):
        if element.hasAttribute(attr_name):
            return element.getAttribute(attr_name)
    return None


# ---------------------------------------------------------------------------
# Signature reference resolution and verification
# ---------------------------------------------------------------------------

def signed_nodes(document) -> list:
    """Resolve every Reference URI to the node selected by the signature.

    A reference is resolved by ID across the whole document.  IDs must be
    unique: if the referenced ID is absent, malformed (not a same-document
    fragment) or shared by more than one element, resolution fails closed and
    an empty list is returned so a duplicate-ID substitution can never be
    silently accepted.
    """
    references = _find_all_local(document, "Reference")
    if not references:
        return []

    elements = list(_iter_elements(document))
    resolved = []

    for reference in references:
        uri = reference.getAttribute("URI")
        if not uri or not uri.startswith("#") or len(uri) == 1:
            return []
        wanted = uri[1:]

        matches = [el for el in elements if _element_id(el) == wanted]
        if len(matches) != 1:
            return []
        resolved.append(matches[0])

    return resolved


def _signature_value(document):
    value_node = _find_first_local(document, "SignatureValue")
    if value_node is None:
        return None
    return _text_content(value_node).strip()


def verify_signature(document, key) -> bool:
    """Verify the HMAC signature carried by an envelope document."""
    try:
        nodes = signed_nodes(document)
        if not nodes:
            return False

        provided = _signature_value(document)
        if not provided:
            return False

        if isinstance(key, str):
            key = key.encode("utf-8")

        # The test vectors carry HMAC-SHA256 as lowercase hexadecimal.
        for node in nodes:
            expected = hmac.new(
                key, canonicalize(node), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(expected, provided):
                return False
        return True
    except Exception:
        # Malformed documents must surface as a rejection, never as a crash.
        return False


# ---------------------------------------------------------------------------
# Claim checks on plain dictionaries
# ---------------------------------------------------------------------------

def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _as_timedelta(value) -> timedelta:
    if isinstance(value, timedelta):
        return value
    if isinstance(value, (int, float)):
        return timedelta(seconds=value)
    return timedelta(0)


def check_conditions(assertion, now, skew) -> dict:
    """Check assertion validity bounds and report a structured decision.

    Boundaries are inclusive.  Clock skew relaxes only the NotBefore edge, so
    it takes effect exactly once rather than widening both ends of the window.
    A future IssueInstant is rejected outright.
    """
    conditions = (assertion or {}).get("conditions") or {}
    now = _as_utc(now)
    skew = _as_timedelta(skew)

    not_before = _as_utc(conditions.get("not_before"))
    not_on_or_after = _as_utc(conditions.get("not_on_or_after"))
    issue_instant = _as_utc(conditions.get("issue_instant"))

    # Boundaries are inclusive.  Skew relaxes the NotBefore edge exactly once
    # and gives the same grace to a slightly future-dated IssueInstant (with
    # zero skew, a future instant is rejected).  It never extends NotOnOrAfter.
    valid = (
        not (issue_instant is not None and issue_instant > now + skew)
        and not (not_before is not None and now < not_before - skew)
        and not (not_on_or_after is not None and now > not_on_or_after)
    )

    return {"valid": valid}


def check_audience(assertion, expected) -> bool:
    """Check that the assertion audience contains the expected service.

    Matching is exact and case-sensitive; prefix/substring comparisons would
    admit look-alike audiences such as ``https://sp.example.attacker``.
    """
    assertion = assertion or {}
    audiences = assertion.get("audiences")
    if audiences is None:
        audiences = (assertion.get("conditions") or {}).get("audiences", [])
    audiences = list(audiences or [])

    if expected is None:
        return False
    if isinstance(expected, str):
        wanted = [expected]
    else:
        wanted = list(expected)

    return any(audience in audiences for audience in wanted)


def check_subject(assertion, request) -> bool:
    """Confirm that the assertion subject matches the requesting principal.

    Only the principal value is compared; NameID format does not change the
    identity and must not make two equal values compare unequal.
    """
    assertion_subject = (assertion or {}).get("subject") or {}
    request_subject = (request or {}).get("subject") or {}

    assertion_value = assertion_subject.get("value")
    request_value = request_subject.get("value")

    return assertion_value is not None and assertion_value == request_value


def replay_guard(store, assertion_id, now, ttl) -> bool:
    """Return True once for an assertion, then False for later replays.

    ``assertion_id`` is an issuer-partitioned key, typically
    ``(issuer, assertion_id)``, so equal IDs from different issuers do not
    collide.  Store values are absolute expiry instants; every call first
    sweeps entries whose expiry has passed.
    """
    now = _as_utc(now)
    ttl = _as_timedelta(ttl)

    expired_keys = []
    for key, expires_at in list(store.items()):
        expires_at = _as_utc(expires_at)
        if expires_at is not None and expires_at <= now:
            expired_keys.append(key)
    for key in expired_keys:
        del store[key]

    if assertion_id in store:
        return False

    store[assertion_id] = now + ttl
    return True


# ---------------------------------------------------------------------------
# Batch validation
# ---------------------------------------------------------------------------

def _parse_xsd_datetime(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return _as_utc(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return _as_utc(datetime.fromisoformat(text))
    except ValueError:
        return None


def _extract_assertion(document) -> dict:
    assertion_element = _find_first_local(document, "Assertion")
    if assertion_element is None:
        raise ValueError("missing Assertion element")

    assertion_id = _element_id(assertion_element)

    issuer_element = _find_first_local(assertion_element, "Issuer")
    issuer = _text_content(issuer_element).strip()

    subject_element = _find_first_local(assertion_element, "Subject")
    name_id = _find_first_local(subject_element, "NameID") if subject_element else None
    subject_value = _text_content(name_id).strip() if name_id is not None else ""
    subject_format = name_id.getAttribute("Format") if name_id is not None else None

    audiences = [
        _text_content(audience).strip()
        for audience in _find_all_local(assertion_element, "Audience")
    ]

    conditions_element = _find_first_local(assertion_element, "Conditions")
    not_before = not_on_or_after = None
    if conditions_element is not None:
        not_before = _parse_xsd_datetime(
            conditions_element.getAttribute("NotBefore") or None
        )
        not_on_or_after = _parse_xsd_datetime(
            conditions_element.getAttribute("NotOnOrAfter") or None
        )
    issue_instant = _parse_xsd_datetime(
        assertion_element.getAttribute("IssueInstant") or None
    )

    return {
        "id": assertion_id,
        "issuer": issuer,
        "subject": {"value": subject_value, "format": subject_format},
        "audiences": audiences,
        "conditions": {
            "not_before": not_before,
            "not_on_or_after": not_on_or_after,
            "issue_instant": issue_instant,
            "audiences": audiences,
        },
    }


def _validate_request(item, policy, now) -> bool:
    document = item.get("document")
    key = item.get("key")
    request = item.get("request") or {}

    if not verify_signature(document, key):
        return False

    assertion = _extract_assertion(document)

    skew = (policy or {}).get("skew", timedelta(0))
    ttl = (policy or {}).get("ttl", timedelta(minutes=5))
    store = (policy or {}).get("replay_store")
    if store is None:
        store = {}

    if not check_conditions(assertion, now, skew).get("valid", False):
        return False
    if not check_audience(assertion, request.get("audience")):
        return False
    if not check_subject(assertion, request):
        return False

    # Consume the issuer-partitioned replay key only after every other check
    # has succeeded, and canonicalize this request's own document freshly so
    # bytes from an earlier batch item can never be reused.
    return replay_guard(store, (assertion["issuer"], assertion["id"]), now, ttl)


def assertion_batch(requests, policy, now) -> dict:
    """Validate a batch of envelopes and return one decision per request."""
    results = {}
    for item in requests:
        name = item.get("name")
        try:
            results[name] = bool(_validate_request(item, policy, now))
        except Exception:
            results[name] = False
    return results
