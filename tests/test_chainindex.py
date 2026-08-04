from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

import pytest

from dewhirlpooler.bitcoin import (
    OutPoint,
    ScriptType,
    Transaction,
    TxInput,
    TxOutput,
    parse_transaction_hex,
)
from dewhirlpooler.blocksource import BlockTransaction, CoreBlock
from dewhirlpooler.chainindex import (
    ChainIndex,
    ChainIndexError,
    ChainIndexReader,
    ChainIndexSettings,
    ChainScanner,
)
from dewhirlpooler.core import CoreRpcError
from dewhirlpooler.whirlpool import DEFAULT_POOLS

FIXTURES = Path(__file__).parent / "fixtures"
START_HEIGHT = 100
POOL_ID = "ashigaru-0.025"
DENOMINATION = 2_500_000


def _fixture(name: str) -> Transaction:
    return parse_transaction_hex((FIXTURES / name).read_text().strip())


def _settings(path: Path, *, start_height: int = START_HEIGHT):
    return ChainIndexSettings(path=path, start_height=start_height)


def _block_hash(height: int, *, branch: int = 0) -> str:
    return f"{branch * 1_000_000 + height + 1:064x}"


def _block(
    height: int,
    transactions: tuple[BlockTransaction, ...] = (),
    *,
    branch: int = 0,
    previous_hash: str | None = None,
) -> CoreBlock:
    if previous_hash is None and height > START_HEIGHT:
        previous_hash = _block_hash(height - 1, branch=branch)
    return CoreBlock(
        height=height,
        block_hash=_block_hash(height, branch=branch),
        previous_block_hash=previous_hash,
        block_time=1_700_000_000 + height,
        transactions=transactions,
    )


def _tx0_block_transaction(
    *,
    txid: str | None = None,
) -> BlockTransaction:
    transaction = _fixture("ashigaru-tx0-0.025.hex")
    if txid is not None:
        transaction = _replace_transaction(transaction, txid=txid)
    output_total = sum(output.value_sats for output in transaction.outputs)
    prevouts = {
        transaction_input.previous_output: TxOutput(
            index=transaction_input.previous_output.index,
            value_sats=output_total + 539,
            script_pubkey=b"\x00\x14" + b"\x91" * 20,
            script_type=ScriptType.P2WPKH,
        )
        for transaction_input in transaction.inputs
    }
    return BlockTransaction(transaction=transaction, prevouts=prevouts)


def _premix_indices(transaction: Transaction) -> tuple[int, ...]:
    return tuple(
        output.index
        for output in transaction.outputs
        if output.value_sats == 2_500_605
    )


def _round_from_tx0(
    tx0: Transaction,
    *,
    txid: str = "a" * 64,
) -> BlockTransaction:
    selected = _premix_indices(tx0)[:5]
    inputs = tuple(
        TxInput(
            previous_output=OutPoint(tx0.txid, index),
            script_sig=b"",
            sequence=0xFFFFFFFD,
            witness=(),
        )
        for index in selected
    )
    outputs = tuple(
        TxOutput(
            index=index,
            value_sats=DENOMINATION,
            script_pubkey=b"\x00\x14" + bytes((index + 1,)) * 20,
            script_type=ScriptType.P2WPKH,
        )
        for index in range(5)
    )
    transaction = Transaction(
        version=2,
        inputs=inputs,
        outputs=outputs,
        lock_time=0,
        has_witness=True,
        txid=txid,
        wtxid=txid,
        size=500,
        weight=1_500,
        vsize=375,
    )
    prevouts = {
        transaction_input.previous_output: tx0.outputs[
            transaction_input.previous_output.index
        ]
        for transaction_input in inputs
    }
    return BlockTransaction(transaction=transaction, prevouts=prevouts)


def _untracked_round(*, txid: str = "b" * 64) -> BlockTransaction:
    inputs = tuple(
        TxInput(
            previous_output=OutPoint(f"{index + 50:064x}", 0),
            script_sig=b"",
            sequence=0xFFFFFFFD,
            witness=(),
        )
        for index in range(5)
    )
    outputs = tuple(
        TxOutput(
            index=index,
            value_sats=DENOMINATION,
            script_pubkey=b"\x00\x14" + bytes((index + 30,)) * 20,
            script_type=ScriptType.P2WPKH,
        )
        for index in range(5)
    )
    transaction = Transaction(
        version=2,
        inputs=inputs,
        outputs=outputs,
        lock_time=0,
        has_witness=True,
        txid=txid,
        wtxid=txid,
        size=500,
        weight=1_500,
        vsize=375,
    )
    prevouts = {
        transaction_input.previous_output: TxOutput(
            index=0,
            value_sats=2_500_605,
            script_pubkey=b"\x00\x14" + bytes((index + 60,)) * 20,
            script_type=ScriptType.P2WPKH,
        )
        for index, transaction_input in enumerate(inputs)
    }
    return BlockTransaction(transaction=transaction, prevouts=prevouts)


def _spend(
    outpoints: tuple[tuple[OutPoint, TxOutput], ...],
    *,
    txid: str,
    fee_sats: int,
    extra_inputs: tuple[tuple[OutPoint, TxOutput], ...] = (),
) -> BlockTransaction:
    all_inputs = outpoints + extra_inputs
    inputs = tuple(
        TxInput(
            previous_output=outpoint,
            script_sig=b"",
            sequence=0xFFFFFFFD,
            witness=(),
        )
        for outpoint, _ in all_inputs
    )
    input_total = sum(output.value_sats for _, output in all_inputs)
    output = TxOutput(
        index=0,
        value_sats=input_total - fee_sats,
        script_pubkey=b"\x00\x14" + b"\xee" * 20,
        script_type=ScriptType.P2WPKH,
    )
    transaction = Transaction(
        version=2,
        inputs=inputs,
        outputs=(output,),
        lock_time=0,
        has_witness=True,
        txid=txid,
        wtxid=txid,
        size=200,
        weight=600,
        vsize=150,
    )
    return BlockTransaction(
        transaction=transaction,
        prevouts=dict(all_inputs),
    )


def _replace_transaction(
    transaction: Transaction,
    *,
    txid: str | None = None,
    outputs: tuple[TxOutput, ...] | None = None,
) -> Transaction:
    return Transaction(
        version=transaction.version,
        inputs=transaction.inputs,
        outputs=transaction.outputs if outputs is None else outputs,
        lock_time=transaction.lock_time,
        has_witness=transaction.has_witness,
        txid=transaction.txid if txid is None else txid,
        wtxid=transaction.wtxid if txid is None else txid,
        size=transaction.size,
        weight=transaction.weight,
        vsize=transaction.vsize,
    )


def _legacy_tx0_block_transaction(
    *,
    txid: str | None = None,
    fee_value_sats: int | None = None,
    extra_fee_like_output: bool = False,
) -> BlockTransaction:
    transaction = _fixture("legacy-tx0-0.05.hex")
    outputs = tuple(
        (
            TxOutput(
                index=output.index,
                value_sats=fee_value_sats,
                script_pubkey=output.script_pubkey,
                script_type=output.script_type,
            )
            if output.index == 1 and fee_value_sats is not None
            else output
        )
        for output in transaction.outputs
    )
    if extra_fee_like_output:
        outputs += (
            TxOutput(
                index=len(outputs),
                value_sats=50_000,
                script_pubkey=b"\x00\x14" + b"\x86" * 20,
                script_type=ScriptType.P2WPKH,
            ),
        )
    transaction = _replace_transaction(
        transaction,
        txid=txid,
        outputs=outputs,
    )
    output_total = sum(output.value_sats for output in transaction.outputs)
    return BlockTransaction(
        transaction=transaction,
        prevouts={
            transaction_input.previous_output: TxOutput(
                index=transaction_input.previous_output.index,
                value_sats=output_total + 1_000,
                script_pubkey=b"\x00\x14" + b"\x87" * 20,
                script_type=ScriptType.P2WPKH,
            )
            for transaction_input in transaction.inputs
        },
    )


def test_settings_defaults_validation_and_immutable_database_start(
    tmp_path: Path,
) -> None:
    settings = ChainIndexSettings.from_env(
        {"DEWHIRLPOOLER_CHAIN_DB": str(tmp_path / "chain.sqlite3")}
    )

    assert settings.start_height == 550_000
    assert settings.busy_timeout_ms == 5_000
    assert settings.prefetch_workers == 8

    with pytest.raises(ValueError, match="START_HEIGHT"):
        ChainIndexSettings.from_env(
            {
                "DEWHIRLPOOLER_CHAIN_DB": str(tmp_path / "bad.sqlite3"),
                "DEWHIRLPOOLER_CHAIN_START_HEIGHT": "-1",
            }
        )
    with pytest.raises(ValueError, match="busy timeout"):
        ChainIndexSettings(
            path=tmp_path / "bad.sqlite3",
            busy_timeout_ms=False,  # type: ignore[arg-type]
        )
    for workers in (0, 17, False, 1.5):
        with pytest.raises(ValueError, match="prefetch workers"):
            ChainIndexSettings(
                path=tmp_path / "bad-prefetch.sqlite3",
                prefetch_workers=workers,  # type: ignore[arg-type]
            )

    path = tmp_path / "immutable.sqlite3"
    ChainIndex(_settings(path)).close()
    with pytest.raises(ChainIndexError, match="start height"):
        ChainIndex(_settings(path, start_height=101))


def test_settings_expand_home_portably(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    settings = ChainIndexSettings.from_env(
        {"DEWHIRLPOOLER_CHAIN_DB": "~/chain.sqlite3"}
    )

    assert settings.path == tmp_path / "chain.sqlite3"


@pytest.mark.parametrize("workers", ["1", "8", "16"])
def test_settings_accept_bounded_prefetch_workers(
    tmp_path: Path,
    workers: str,
) -> None:
    settings = ChainIndexSettings.from_env(
        {
            "DEWHIRLPOOLER_CHAIN_DB": str(tmp_path / "chain.sqlite3"),
            "DEWHIRLPOOLER_CHAIN_PREFETCH_WORKERS": workers,
        }
    )

    assert settings.prefetch_workers == int(workers)


@pytest.mark.parametrize(
    "workers",
    ["0", "-1", "17", " 8", "8 ", "08", "+8", "1.5", "many"],
)
def test_settings_reject_invalid_prefetch_workers(
    tmp_path: Path,
    workers: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="DEWHIRLPOOLER_CHAIN_PREFETCH_WORKERS",
    ):
        ChainIndexSettings.from_env(
            {
                "DEWHIRLPOOLER_CHAIN_DB": str(tmp_path / "chain.sqlite3"),
                "DEWHIRLPOOLER_CHAIN_PREFETCH_WORKERS": workers,
            }
        )


def test_schema_pragmas_constraints_and_query_plans(tmp_path: Path) -> None:
    path = tmp_path / "chain.sqlite3"
    with ChainIndex(_settings(path)):
        pass

    connection = sqlite3.connect(path)
    assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
    indexes = {
        row[0]
        for row in connection.execute(
            """
            SELECT name
            FROM sqlite_master
            WHERE type = 'index' AND sql IS NOT NULL
            """
        )
    }
    assert {
        "pool_utxos_active",
        "pool_snapshots_pool_height",
        "indexed_tx0s_height_pool",
        "indexed_rounds_height_pool",
        "coordinator_fee_utxos_active",
        "coordinator_spends_height",
    } <= indexes
    pool_plan = " ".join(
        str(row)
        for row in connection.execute(
            """
            EXPLAIN QUERY PLAN
            SELECT *
            FROM pool_snapshots
            WHERE pool_id = ? AND height BETWEEN ? AND ?
            ORDER BY height
            """,
            (POOL_ID, 100, 200),
        )
    )
    active_plan = " ".join(
        str(row)
        for row in connection.execute(
            """
            EXPLAIN QUERY PLAN
            SELECT txid, vout
            FROM pool_utxos
            WHERE pool_id = ? AND spent_height IS NULL
            """,
            (POOL_ID,),
        )
    )
    latest_plan = " ".join(
        str(row)
        for row in connection.execute(
            """
            EXPLAIN QUERY PLAN
            SELECT pool_id, MAX(height)
            FROM pool_snapshots
            GROUP BY pool_id
            """
        )
    )
    coordinator_plan = " ".join(
        str(row)
        for row in connection.execute(
            """
            EXPLAIN QUERY PLAN
            SELECT txid, vout
            FROM coordinator_fee_utxos
            WHERE spent_height IS NULL
            ORDER BY created_height
            """
        )
    )
    assert "pool_snapshots_pool_height" in pool_plan
    assert "pool_utxos_active" in active_plan
    assert "pool_snapshots_pool_height" in latest_plan
    assert "coordinator_fee_utxos_active" in coordinator_plan
    connection.close()


def test_reader_is_read_only_and_reports_existing_index(
    tmp_path: Path,
) -> None:
    path = tmp_path / "chain.sqlite3"
    with ChainIndex(_settings(path)) as index:
        index.apply_block(
            _block(START_HEIGHT, (_tx0_block_transaction(),))
        )

    with ChainIndexReader(path) as reader:
        status = reader.status()
        snapshots = reader.latest_pool_snapshots()
        summary = reader.coordinator_summary()

        assert status.start_height == START_HEIGHT
        assert status.last_height == START_HEIGHT
        assert status.last_block_hash == _block_hash(START_HEIGHT)
        assert status.blocks_indexed == 1
        assert status.tip_height is None
        assert status.complete_to_tip is False
        assert reader._connection.execute(  # noqa: SLF001
            "PRAGMA query_only"
        ).fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            reader._connection.execute(  # noqa: SLF001
                "DELETE FROM chain_blocks"
            )

    assert len(snapshots) == len(DEFAULT_POOLS)
    assert summary.gross_revenue_sats == 125_000


def test_reader_observes_concurrent_wal_commits(tmp_path: Path) -> None:
    path = tmp_path / "chain.sqlite3"
    with ChainIndex(_settings(path)) as writer:
        writer.apply_block(_block(START_HEIGHT))
        with ChainIndexReader(path) as reader:
            assert reader.status().last_height == START_HEIGHT

            writer.apply_block(_block(START_HEIGHT + 1))

            assert reader.status().last_height == START_HEIGHT + 1
            assert [
                item.height
                for item in reader.pool_history(POOL_ID, limit=10)
            ] == [START_HEIGHT, START_HEIGHT + 1]


def test_reader_history_is_bounded_filtered_and_ordered(
    tmp_path: Path,
) -> None:
    path = tmp_path / "chain.sqlite3"
    with ChainIndex(_settings(path)) as index:
        for height in range(START_HEIGHT, START_HEIGHT + 6):
            index.apply_block(_block(height))

    with ChainIndexReader(path) as reader:
        assert [
            item.height
            for item in reader.pool_history(POOL_ID, limit=3)
        ] == [START_HEIGHT + 3, START_HEIGHT + 4, START_HEIGHT + 5]
        assert [
            item.height
            for item in reader.pool_history(
                POOL_ID,
                start_height=START_HEIGHT + 1,
                end_height=START_HEIGHT + 4,
                limit=2,
            )
        ] == [START_HEIGHT + 3, START_HEIGHT + 4]


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"pool_id": "unknown"}, "unsupported"),
        ({"pool_id": POOL_ID, "start_height": -1}, "Start height"),
        ({"pool_id": POOL_ID, "end_height": False}, "End height"),
        (
            {
                "pool_id": POOL_ID,
                "start_height": START_HEIGHT + 1,
                "end_height": START_HEIGHT,
            },
            "may not exceed",
        ),
        ({"pool_id": POOL_ID, "limit": 0}, "History limit"),
        ({"pool_id": POOL_ID, "limit": 2_001}, "History limit"),
        ({"pool_id": POOL_ID, "limit": True}, "History limit"),
    ],
)
def test_reader_history_rejects_invalid_bounds(
    tmp_path: Path,
    kwargs: dict[str, object],
    message: str,
) -> None:
    path = tmp_path / "chain.sqlite3"
    with ChainIndex(_settings(path)):
        pass
    with ChainIndexReader(path) as reader:
        with pytest.raises(ValueError, match=message):
            reader.pool_history(**kwargs)  # type: ignore[arg-type]


def test_reader_rejects_missing_or_incompatible_database_safely(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "private-host-chain.sqlite3"
    with pytest.raises(ChainIndexError) as missing_error:
        ChainIndexReader(missing)
    assert str(missing) not in str(missing_error.value)

    malformed = tmp_path / "malformed.sqlite3"
    malformed.write_bytes(b"not a sqlite database")
    with pytest.raises(ChainIndexError) as malformed_error:
        ChainIndexReader(malformed)
    assert str(malformed) not in str(malformed_error.value)
    assert "sqlite" not in str(malformed_error.value).lower()

    incompatible = tmp_path / "incompatible.sqlite3"
    with ChainIndex(_settings(incompatible)):
        pass
    connection = sqlite3.connect(incompatible)
    connection.execute(
        "UPDATE chain_meta SET value = '999' WHERE key = 'schema_version'"
    )
    connection.commit()
    connection.close()
    with pytest.raises(ChainIndexError, match="unsupported"):
        ChainIndexReader(incompatible)


def test_tx0_adds_liquidity_and_coordinator_revenue(tmp_path: Path) -> None:
    tx0 = _tx0_block_transaction()
    with ChainIndex(_settings(tmp_path / "chain.sqlite3")) as index:
        index.apply_block(_block(START_HEIGHT, (tx0,)))

        snapshot = index.pool_snapshot(POOL_ID, START_HEIGHT)
        assert snapshot is not None
        assert snapshot.liquidity_sats == 9 * DENOMINATION
        assert snapshot.utxo_count == 9
        assert snapshot.entry_sats == 9 * DENOMINATION
        assert snapshot.exit_sats == 0
        assert snapshot.tx0_count == 1
        assert snapshot.round_count == 0
        zero_snapshots = [
            item
            for item in index.latest_pool_snapshots()
            if item.pool_id != POOL_ID
        ]
        assert len(zero_snapshots) == len(DEFAULT_POOLS) - 1
        assert all(item.liquidity_sats == 0 for item in zero_snapshots)

        summary = index.coordinator_summary()
        assert summary.gross_revenue_sats == 125_000
        assert summary.known_mining_cost_sats == 0
        assert summary.net_known_profit_sats == 125_000
        assert summary.fee_output_count == 1
        assert summary.ambiguous_spend_count == 0


def test_round_rollover_preserves_liquidity_and_exit_reduces_it(
    tmp_path: Path,
) -> None:
    tx0 = _tx0_block_transaction()
    round_transaction = _round_from_tx0(tx0.transaction)
    exit_transaction = _spend(
        (
            (
                OutPoint(round_transaction.transaction.txid, 0),
                round_transaction.transaction.outputs[0],
            ),
        ),
        txid="c" * 64,
        fee_sats=500,
    )
    with ChainIndex(_settings(tmp_path / "chain.sqlite3")) as index:
        index.apply_block(_block(100, (tx0,)))
        index.apply_block(_block(101, (round_transaction,)))

        rollover = index.pool_snapshot(POOL_ID, 101)
        assert rollover is not None
        assert rollover.liquidity_sats == 9 * DENOMINATION
        assert rollover.entry_sats == 0
        assert rollover.exit_sats == 0
        assert rollover.round_count == 1

        index.apply_block(_block(102, (exit_transaction,)))
        exit_snapshot = index.pool_snapshot(POOL_ID, 102)
        assert exit_snapshot is not None
        assert exit_snapshot.liquidity_sats == 8 * DENOMINATION
        assert exit_snapshot.exit_sats == DENOMINATION
        assert exit_snapshot.utxo_count == 8


def test_untracked_round_does_not_mint_liquidity(tmp_path: Path) -> None:
    round_transaction = _untracked_round()
    with ChainIndex(_settings(tmp_path / "chain.sqlite3")) as index:
        index.apply_block(_block(100, (round_transaction,)))

        snapshot = index.pool_snapshot(POOL_ID, 100)
        assert snapshot is not None
        assert snapshot.liquidity_sats == 0
        assert snapshot.round_count == 1
        connection = sqlite3.connect(index.settings.path)
        row = connection.execute(
            "SELECT liquidity_rollover FROM indexed_rounds"
        ).fetchone()
        assert row == (0,)
        connection.close()


def test_coordinator_pure_and_ambiguous_spends(tmp_path: Path) -> None:
    first = _tx0_block_transaction(txid="1" * 64)
    second = _tx0_block_transaction(txid="2" * 64)
    fee_output = first.transaction.outputs[1]
    pure_spend = _spend(
        ((OutPoint(first.transaction.txid, 1), fee_output),),
        txid="3" * 64,
        fee_sats=1_000,
    )
    unrelated = (
        OutPoint("4" * 64, 0),
        TxOutput(
            index=0,
            value_sats=50_000,
            script_pubkey=b"\x00\x14" + b"\x44" * 20,
            script_type=ScriptType.P2WPKH,
        ),
    )
    ambiguous_spend = _spend(
        (
            (
                OutPoint(second.transaction.txid, 1),
                second.transaction.outputs[1],
            ),
        ),
        txid="5" * 64,
        fee_sats=2_000,
        extra_inputs=(unrelated,),
    )

    with ChainIndex(_settings(tmp_path / "chain.sqlite3")) as index:
        index.apply_block(_block(100, (first,)))
        index.apply_block(_block(101, (second,)))
        index.apply_block(_block(102, (pure_spend, ambiguous_spend)))

        summary = index.coordinator_summary()
        assert summary.gross_revenue_sats == 250_000
        assert summary.known_mining_cost_sats == 1_000
        assert summary.net_known_profit_sats == 249_000
        assert summary.ambiguous_spend_count == 1
        assert summary.ambiguous_input_sats == 125_000


def test_same_block_tx0_round_and_coordinator_spend_are_atomic(
    tmp_path: Path,
) -> None:
    tx0 = _tx0_block_transaction()
    round_transaction = _round_from_tx0(tx0.transaction)
    coordinator_spend = _spend(
        (
            (
                OutPoint(tx0.transaction.txid, 1),
                tx0.transaction.outputs[1],
            ),
        ),
        txid="7" * 64,
        fee_sats=125_000,
    )

    with ChainIndex(_settings(tmp_path / "chain.sqlite3")) as index:
        index.apply_block(
            _block(
                START_HEIGHT,
                (tx0, round_transaction, coordinator_spend),
            )
        )

        snapshot = index.pool_snapshot(POOL_ID, START_HEIGHT)
        assert snapshot is not None
        assert snapshot.liquidity_sats == 9 * DENOMINATION
        assert snapshot.entry_sats == 9 * DENOMINATION
        assert snapshot.exit_sats == 0
        assert snapshot.round_count == 1
        summary = index.coordinator_summary()
        assert summary.gross_revenue_sats == 125_000
        assert summary.known_mining_cost_sats == 125_000
        assert summary.net_known_profit_sats == 0

        connection = sqlite3.connect(index.settings.path)
        spent = connection.execute(
            """
            SELECT spent_height, spent_txid
            FROM coordinator_fee_utxos
            """
        ).fetchone()
        assert spent == (START_HEIGHT, coordinator_spend.transaction.txid)
        assert connection.execute(
            """
            SELECT COUNT(*)
            FROM coordinator_fee_utxos
            WHERE spent_height IS NULL
            """
        ).fetchone() == (0,)
        connection.close()


def test_discounted_legacy_fee_is_inferred_by_known_script(
    tmp_path: Path,
) -> None:
    standard = _legacy_tx0_block_transaction()
    discounted = _legacy_tx0_block_transaction(
        txid="8" * 64,
        fee_value_sats=100_000,
    )

    with ChainIndex(_settings(tmp_path / "chain.sqlite3")) as index:
        index.apply_block(_block(START_HEIGHT, (standard,)))
        index.apply_block(_block(START_HEIGHT + 1, (discounted,)))

        connection = sqlite3.connect(index.settings.path)
        row = connection.execute(
            """
            SELECT value_sats, confidence, method
            FROM coordinator_fee_utxos
            WHERE txid = ?
            """,
            (discounted.transaction.txid,),
        ).fetchone()
        assert row == (
            100_000,
            "medium",
            "discounted_fee_script_reuse",
        )
        connection.close()


def test_discounted_legacy_amount_evidence_and_ambiguity(
    tmp_path: Path,
) -> None:
    discounted = _legacy_tx0_block_transaction(
        txid="9" * 64,
        fee_value_sats=100_000,
    )
    ambiguous = _legacy_tx0_block_transaction(
        txid="a" * 64,
        fee_value_sats=100_000,
        extra_fee_like_output=True,
    )

    with ChainIndex(_settings(tmp_path / "chain.sqlite3")) as index:
        index.apply_block(_block(START_HEIGHT, (ambiguous,)))
        index.apply_block(_block(START_HEIGHT + 1, (discounted,)))

        connection = sqlite3.connect(index.settings.path)
        inferred = connection.execute(
            """
            SELECT value_sats, confidence, method
            FROM coordinator_fee_utxos
            WHERE txid = ?
            """,
            (discounted.transaction.txid,),
        ).fetchone()
        assert inferred == (
            100_000,
            "medium",
            "discounted_fee_amount",
        )
        ambiguous_fee = connection.execute(
            """
            SELECT coordinator_fee_sats, coordinator_fee_method
            FROM indexed_tx0s
            WHERE txid = ?
            """,
            (ambiguous.transaction.txid,),
        ).fetchone()
        assert ambiguous_fee == (0, None)
        connection.close()


def test_reopen_resume_and_rollback_restores_spent_utxo(
    tmp_path: Path,
) -> None:
    path = tmp_path / "chain.sqlite3"
    tx0 = _tx0_block_transaction()
    exit_transaction = _spend(
        (
            (
                OutPoint(tx0.transaction.txid, 3),
                tx0.transaction.outputs[3],
            ),
        ),
        txid="6" * 64,
        fee_sats=605,
    )
    with ChainIndex(_settings(path)) as index:
        index.apply_block(_block(100, (tx0,)))
        index.apply_block(_block(101, (exit_transaction,)))
        assert index.pool_snapshot(POOL_ID, 101).liquidity_sats == (
            8 * DENOMINATION
        )

    with ChainIndex(_settings(path)) as reopened:
        assert reopened.status().last_height == 101
        assert reopened.rollback_after(100) == 1
        snapshot = reopened.pool_snapshot(POOL_ID, 100)
        assert snapshot is not None
        assert snapshot.liquidity_sats == 9 * DENOMINATION
        connection = sqlite3.connect(path)
        active = connection.execute(
            """
            SELECT COUNT(*)
            FROM pool_utxos
            WHERE spent_height IS NULL
            """
        ).fetchone()[0]
        assert active == 9
        connection.close()


def test_failed_block_is_atomic_and_does_not_advance_memory(
    tmp_path: Path,
) -> None:
    tx0 = _tx0_block_transaction()
    duplicate = _tx0_block_transaction()
    with ChainIndex(_settings(tmp_path / "chain.sqlite3")) as index:
        index.apply_block(_block(100, (tx0,)))
        with pytest.raises(ChainIndexError, match="apply"):
            index.apply_block(_block(101, (duplicate,)))

        assert index.status().last_height == 100
        assert index.pool_snapshot(POOL_ID, 100).liquidity_sats == (
            9 * DENOMINATION
        )
        index.apply_block(_block(101))
        assert index.status().last_height == 101


class _FakeSource:
    def __init__(
        self,
        blocks: dict[int, CoreBlock],
        *,
        tip: int,
        rpc_failures: int = 0,
    ) -> None:
        self.blocks = blocks
        self.tip = tip
        self.rpc_failures = rpc_failures
        self.block_calls: list[int] = []

    def chain_height(self) -> int:
        return self.tip

    def block_hash_at_height(self, height: int) -> str:
        return self.blocks[height].block_hash

    def block_at_height(self, height: int) -> CoreBlock:
        self.block_calls.append(height)
        if self.rpc_failures:
            self.rpc_failures -= 1
            raise CoreRpcError("safe failure")
        return self.blocks[height]


def test_scanner_retries_resumes_and_reports_progress(tmp_path: Path) -> None:
    blocks = {
        100: _block(100),
        101: _block(101),
        102: _block(102),
    }
    source = _FakeSource(blocks, tip=102, rpc_failures=2)
    delays: list[int] = []
    progress: list[tuple[int, int]] = []
    with ChainIndex(_settings(tmp_path / "chain.sqlite3")) as index:
        scanner = ChainScanner(
            source,  # type: ignore[arg-type]
            index,
            retry_delay=delays.append,
        )
        result = scanner.scan(
            max_blocks=2,
            progress=lambda height, tip: progress.append((height, tip)),
        )

        assert result.blocks_scanned == 2
        assert result.start_height == 100
        assert result.stop_height == 101
        assert delays == [1, 2]
        assert progress == [(100, 102), (101, 102)]

        resumed = scanner.scan()
        assert resumed.blocks_scanned == 1
        assert resumed.start_height == 102
        assert index.status(tip_height=102).complete_to_tip is True


def test_scanner_uses_three_bounded_retries(tmp_path: Path) -> None:
    source = _FakeSource(
        {100: _block(100)},
        tip=100,
        rpc_failures=3,
    )
    delays: list[int] = []
    with ChainIndex(_settings(tmp_path / "chain.sqlite3")) as index:
        result = ChainScanner(
            source,  # type: ignore[arg-type]
            index,
            retry_delay=delays.append,
        ).scan()

    assert result.blocks_scanned == 1
    assert delays == [1, 2, 4]


def test_scanner_prefetches_but_applies_blocks_in_height_order(
    tmp_path: Path,
) -> None:
    blocks = {
        height: _block(height)
        for height in range(100, 108)
    }

    class ConcurrentSource(_FakeSource):
        def __init__(self) -> None:
            super().__init__(blocks, tip=107)
            self.lock = threading.Lock()
            self.active = 0
            self.max_active = 0

        def block_at_height(self, height: int) -> CoreBlock:
            with self.lock:
                self.active += 1
                self.max_active = max(self.max_active, self.active)
            try:
                time.sleep(0.01)
                return self.blocks[height]
            finally:
                with self.lock:
                    self.active -= 1

    source = ConcurrentSource()
    with ChainIndex(_settings(tmp_path / "chain.sqlite3")) as index:
        result = ChainScanner(  # type: ignore[arg-type]
            source,
            index,
            prefetch_workers=4,
        ).scan()

        assert result.blocks_scanned == 8
        assert index.status().last_height == 107
        assert tuple(
            index.block_hash(height) for height in range(100, 108)
        ) == tuple(blocks[height].block_hash for height in range(100, 108))
    assert source.max_active > 1
    assert source.max_active <= 4


@pytest.mark.parametrize("workers", [0, 17, True])
def test_scanner_rejects_unbounded_prefetch(
    tmp_path: Path,
    workers: object,
) -> None:
    with ChainIndex(_settings(tmp_path / "chain.sqlite3")) as index:
        with pytest.raises(ValueError, match="Prefetch workers"):
            ChainScanner(
                _FakeSource({100: _block(100)}, tip=100),  # type: ignore[arg-type]
                index,
                prefetch_workers=workers,  # type: ignore[arg-type]
            )


def test_scanner_rolls_back_competing_tip(tmp_path: Path) -> None:
    original = {
        100: _block(100),
        101: _block(101),
        102: _block(102),
    }
    replacement_101 = _block(
        101,
        branch=1,
        previous_hash=original[100].block_hash,
    )
    replacement_102 = _block(
        102,
        branch=1,
        previous_hash=replacement_101.block_hash,
    )
    replacement = {
        100: original[100],
        101: replacement_101,
        102: replacement_102,
    }
    path = tmp_path / "chain.sqlite3"
    with ChainIndex(_settings(path)) as index:
        ChainScanner(  # type: ignore[arg-type]
            _FakeSource(original, tip=102),
            index,
        ).scan()
        result = ChainScanner(  # type: ignore[arg-type]
            _FakeSource(replacement, tip=102),
            index,
        ).scan()

        assert result.reorg_blocks_rolled_back == 2
        assert result.blocks_scanned == 2
        assert index.block_hash(102) == replacement_102.block_hash


def test_scanner_rejects_reorg_below_start(tmp_path: Path) -> None:
    original = {100: _block(100)}
    replacement = {100: _block(100, branch=1)}
    path = tmp_path / "chain.sqlite3"
    with ChainIndex(_settings(path)) as index:
        ChainScanner(  # type: ignore[arg-type]
            _FakeSource(original, tip=100),
            index,
        ).scan()
        with pytest.raises(ChainIndexError, match="crossed"):
            ChainScanner(  # type: ignore[arg-type]
                _FakeSource(replacement, tip=100),
                index,
            ).scan()
