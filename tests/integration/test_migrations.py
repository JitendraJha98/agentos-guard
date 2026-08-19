"""The migration chain, run for real against a scratch database.

There were no migration tests before this file, which was survivable while every migration only
ADDED an empty table: nothing it did could make a claim about data that already existed. ECON-03's
0026 is the first that widens a populated one, and its central promise — that a row recorded before
the migration comes back with NULLs and not with defaults — is a promise about rows nobody can
re-observe. A `server_default` slipped into it would pass every other test in this suite while
turning "we did not measure" into "we measured nothing" for the entire historical ledger.
"""

from __future__ import annotations

import pathlib
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPTS = "packages/controlplane/src/agentos_controlplane/store/migrations"


@pytest.fixture
def alembic_on_a_scratch_db(tmp_path, monkeypatch):
    """A real file DB, not `:memory:` — alembic opens its own connections and an in-memory database
    would be a different, empty one each time."""
    monkeypatch.chdir(_ROOT)  # alembic.ini lives at the repo root and holds relative paths
    url = "sqlite+pysqlite:///" + pathlib.Path(tmp_path, "chain.db").as_posix()
    config = Config(str(_ROOT / "alembic.ini"))
    config.set_main_option("script_location", _SCRIPTS)
    config.set_main_option("sqlalchemy.url", url)
    return config, create_engine(url)


def _insert_legacy_cost_row(engine) -> None:
    """One row as 0025 knew how to write it: tokens and dollars, no provider, no GPU columns."""
    with engine.begin() as c:
        c.execute(
            text(
                "INSERT INTO cost_record (id, action_id, agent_id, action_type, model, "
                "input_tokens, output_tokens, cost_micro_usd, price_book_version) "
                "VALUES (:id, :aid, 'a1', 'model_invocation', 'gpt-4o', 100, 20, 500, 'v1')"
            ),
            {"id": uuid4().bytes, "aid": uuid4().bytes},
        )


def test_0026_does_not_backfill_the_rows_it_finds(alembic_on_a_scratch_db) -> None:
    """An action recorded before ECON-03 genuinely has no provider and no GPU reading. Defaulting
    the new columns to 0 / 'process' would make every historical row assert "this agent's process
    used 0 MiB of GPU" — and `totals()` matches on that label, so the agent would report
    `gpu_process_memory_mib_max: 0` instead of None. That is the D-7 fabrication this slice exists
    to refuse, applied retroactively to actions nobody ever measured.
    """
    config, engine = alembic_on_a_scratch_db
    command.upgrade(config, "0025_agent_budget")
    _insert_legacy_cost_row(engine)

    command.upgrade(config, "head")

    with engine.begin() as c:
        row = c.execute(
            text("SELECT provider, gpu_seconds, gpu_memory_mib, gpu_attribution FROM cost_record")
        ).one()
    assert row == (None, None, None, None)


def test_0026_is_reversible_without_taking_the_pre_existing_row_with_it(
    alembic_on_a_scratch_db,
) -> None:
    """A migration an operator cannot back out of is one they will not apply. The four columns go
    away on downgrade and the ledger row they were added beside survives the round trip — the row
    is the money; the columns are what ECON-03 added next to it."""
    config, engine = alembic_on_a_scratch_db
    command.upgrade(config, "0025_agent_budget")
    _insert_legacy_cost_row(engine)
    command.upgrade(config, "head")

    command.downgrade(config, "0025_agent_budget")

    with engine.begin() as c:
        assert c.execute(text("SELECT count(*) FROM cost_record")).scalar_one() == 1
        columns = {r[1] for r in c.execute(text("PRAGMA table_info(cost_record)"))}
    assert not columns & {"provider", "gpu_seconds", "gpu_memory_mib", "gpu_attribution"}

    command.upgrade(config, "head")  # and forward again, so the branch is not one-way

    with engine.begin() as c:
        assert c.execute(text("SELECT count(*) FROM cost_record")).scalar_one() == 1


def _insert_legacy_agent_row(engine) -> None:
    """One agent as 0026 knew how to write it: no risk classification column at all."""
    with engine.begin() as c:
        c.execute(text("INSERT INTO agent (agent_id, trust_score) VALUES ('a1', 0.5)"))


def test_0027_does_not_backfill_a_risk_classification(alembic_on_a_scratch_db) -> None:
    """An agent registered before CMP-04 genuinely has no declaration on file, and this is the one
    column in the schema where a default is a legal claim about someone else's deployment.
    'minimal_risk' would tell a deployer to skip obligations they may have; 'high_risk' would
    burden them with obligations they do not. NULL is the only honest value, and the export turns
    it into "undeclared".
    """
    config, engine = alembic_on_a_scratch_db
    command.upgrade(config, "0026_cost_provider_gpu")
    _insert_legacy_agent_row(engine)

    command.upgrade(config, "head")

    with engine.begin() as c:
        assert c.execute(text("SELECT risk_classification FROM agent")).scalar_one() is None


def test_0027_is_reversible_without_taking_the_agent_with_it(alembic_on_a_scratch_db) -> None:
    """The declaration is an annotation on a registered agent; backing the migration out must drop
    the annotation, never the identity it was attached to."""
    config, engine = alembic_on_a_scratch_db
    command.upgrade(config, "0026_cost_provider_gpu")
    _insert_legacy_agent_row(engine)
    command.upgrade(config, "head")
    with engine.begin() as c:
        c.execute(text("UPDATE agent SET risk_classification = 'high_risk'"))

    command.downgrade(config, "0026_cost_provider_gpu")

    with engine.begin() as c:
        assert c.execute(text("SELECT count(*) FROM agent")).scalar_one() == 1
        columns = {r[1] for r in c.execute(text("PRAGMA table_info(agent)"))}
    assert "risk_classification" not in columns

    command.upgrade(config, "head")  # and forward again, so the branch is not one-way

    with engine.begin() as c:
        # The declaration did NOT survive the round trip, and must come back as undeclared rather
        # than as whatever it was before — a dropped column is dropped data, and re-adding it must
        # not resurrect a legal classification nobody re-declared.
        assert c.execute(text("SELECT risk_classification FROM agent")).scalar_one() is None


def test_the_migration_chain_has_exactly_one_head(alembic_on_a_scratch_db) -> None:
    """Two heads is the failure mode of parallel slices on one branch, and it does not show up
    until an operator runs `upgrade head` and gets an error instead of a schema."""
    from alembic.script import ScriptDirectory

    config, _ = alembic_on_a_scratch_db

    heads = ScriptDirectory.from_config(config).get_revisions("heads")

    assert len(heads) == 1, [h.revision for h in heads]
