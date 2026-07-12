"""agentos-sdk — the data-plane PEP (INT-01..06 / SDK-01).

Phase 1 governed tool calls (INT-01). Phase 2 extends interception to all five action
types: tool + model via the LangChain `GovernanceMiddleware` hooks, and memory + MCP +
delegation via the `governed_*` wrappers — all sharing one enforcement core
(`enforce`) and one coverage registry (`coverage`, INT-06: no silent gaps).
"""

from agentos_sdk.client import ControlPlaneClient, ControlPlaneError
from agentos_sdk.coverage import (
    InterceptionGapError,
    coverage_matrix,
    covered_types,
    covers,
    verify_coverage,
)
from agentos_sdk.enforce import (
    ApprovalCoordinator,
    GovernanceDenied,
    SideEffectDispatcher,
    format_reasons,
    governed_call,
)
from agentos_sdk.middleware import GovernanceMiddleware
from agentos_sdk.normalize import (
    normalize_action,
    normalize_delegation,
    normalize_memory_access,
    normalize_mcp_call,
    normalize_model_call,
)
from agentos_sdk.redteam import (
    BLOCKING_OUTCOMES,
    Attack,
    AttackResult,
    Results,
    run_suite,
    suites,
)
from agentos_sdk.wrappers import (
    governed_delegation,
    governed_memory_access,
    governed_mcp_call,
)

__all__ = [
    # control-plane client (SDK-02/04: self-register + resource CRUD + approvals)
    "ControlPlaneClient",
    "ControlPlaneError",
    # PEP middleware (tool + model native hooks)
    "GovernanceMiddleware",
    # normalizers (one per action type)
    "normalize_action",
    "normalize_model_call",
    "normalize_memory_access",
    "normalize_mcp_call",
    "normalize_delegation",
    # governed wrappers (memory / MCP / delegation)
    "governed_memory_access",
    "governed_mcp_call",
    "governed_delegation",
    # shared enforcement core (the one outcome map + its injected seams)
    "governed_call",
    "GovernanceDenied",
    "format_reasons",
    "ApprovalCoordinator",
    "SideEffectDispatcher",
    # interception coverage (INT-06)
    "covers",
    "covered_types",
    "coverage_matrix",
    "verify_coverage",
    "InterceptionGapError",
    # pytest-native red-team harness + curated corpus (SDK-03 / TEST-01/03/04)
    "run_suite",
    "suites",
    "Attack",
    "AttackResult",
    "Results",
    "BLOCKING_OUTCOMES",
]
