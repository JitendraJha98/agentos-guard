"""Canonical form + content-hash version (POL-08 key): order-invariant, content-sensitive."""
import pytest
from agentos_constitution.schema import Constitution
from agentos_constitution.version import constitution_version


def _principles(statement_suffix=""):
    return [
        {
            "id": "1.1",
            "title": "Egress allowlist",
            "statement": "Only allowlisted hosts." + statement_suffix,
            "effect": "deny",
            "when": {"field": "egress.host", "op": "not_in", "list_ref": "egress_allowlist"},
        },
        {
            "id": "2.1",
            "title": "Destruction needs approval",
            "statement": "Destructive actions require approval." + statement_suffix,
            "effect": "require_approval",
            "when": {"field": "intent.class", "op": "eq", "value": "DATA_DESTRUCTION"},
        },
    ]


@pytest.fixture
def small_constitution_factory():
    def make(order="forward", statement_suffix=""):
        principles = _principles(statement_suffix)
        hosts = ["api.example.com", "internal.example.com"]
        if order == "reversed":
            principles = list(reversed(principles))
            hosts = list(reversed(hosts))
        return Constitution(
            schema_version=1, name="small",
            principles=principles, lists={"egress_allowlist": hosts},
        )

    return make


@pytest.fixture
def small_constitution(small_constitution_factory):
    return small_constitution_factory()


def test_version_is_sha256_prefixed(small_constitution):
    v = constitution_version(small_constitution)
    assert v.startswith("sha256:") and len(v) == 7 + 64


def test_version_invariant_to_principle_and_list_order(small_constitution_factory):
    a = small_constitution_factory(order="forward")    # same content, different YAML order
    b = small_constitution_factory(order="reversed")
    assert constitution_version(a) == constitution_version(b)


def test_version_changes_when_statement_changes(small_constitution_factory):
    a = small_constitution_factory()
    b = small_constitution_factory(statement_suffix=" v2")
    assert constitution_version(a) != constitution_version(b)
