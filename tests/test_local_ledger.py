# SPDX-License-Identifier: Apache-2.0
# Copyright Contributors to the Universal Plug Protocol project
"""LocalLedger's log is hash-chained: inserted, edited, reordered, or backdated lines break it."""
import json
import multiprocessing

import pytest

from upp import ANY, Attestation, LocalLedger, Plug, PlugError, canonical, sha256_hex
from upp.ledgers.local import GENESIS


def writer(path, n=3):
    p = Plug(trust={"log": ANY})
    p.register("log", LocalLedger(str(path)))
    p.open("log")
    return p, [Attestation.from_receipt(p.prove(f"fact {i}", "doc.sha256")) for i in range(n)]


def reader(path):
    q = Plug(trust={"log": ANY})
    q.register("log", LocalLedger(str(path)))
    return q


def lines(path):
    return [json.loads(x) for x in path.read_text().splitlines()]


def rewrite(path, records):
    path.write_text("".join(canonical(r) + "\n" for r in records))


def test_records_chain_from_genesis_and_head_names_the_last(tmp_path):
    path = tmp_path / "log.jsonl"
    _, atts = writer(path)
    recs = lines(path)
    assert [r["seq"] for r in recs] == [0, 1, 2] and recs[0]["prev"] == GENESIS
    for a, b in zip(recs, recs[1:]):
        assert b["prev"] == sha256_hex(canonical(a)) and b["anchored_at"] >= a["anchored_at"]
    assert LocalLedger(str(path)).head() == {"seq": 2, "hash": sha256_hex(canonical(recs[-1]))}
    assert all(reader(path).check(a)["valid"] for a in atts)


@pytest.mark.parametrize("tamper", ["backdate", "edit", "insert", "reorder", "drop"])
def test_tampering_breaks_the_chain_from_that_line_on(tmp_path, tamper):
    path = tmp_path / "log.jsonl"
    _, atts = writer(path)
    recs = lines(path)
    if tamper == "backdate":
        recs[1]["anchored_at"] = "2000-01-01T00:00:00.000000Z"
    elif tamper == "edit":
        recs[1]["issuer"] = "did:key:z6MkSomeoneElse"
    elif tamper == "insert":
        recs.insert(1, dict(recs[0], statement_hash="ab" * 32, seq=1))
    elif tamper == "reorder":
        recs[1], recs[2] = recs[2], recs[1]
    else:
        del recs[1]
    rewrite(path, recs)
    q = reader(path)
    assert q.check(atts[0])["valid"] is True  # what precedes the break still holds
    v = q.check(atts[2])
    assert v["valid"] is False and "chain breaks" in v["receipt"].error


def test_a_backdated_line_appended_at_the_end_is_refused(tmp_path):
    path = tmp_path / "log.jsonl"
    writer(path)
    recs = lines(path)
    forged = {"network": "log", "statement_hash": "cd" * 32, "subject_hash": "ef" * 32, "issuer": recs[0]["issuer"],
              "anchored_at": "2000-01-01T00:00:00.000000Z", "seq": 3, "prev": sha256_hex(canonical(recs[-1]))}
    with open(path, "a") as f:
        f.write(canonical(forged) + "\n")
    ledger = LocalLedger(str(path))
    assert ledger.head()["seq"] == 2 and ("log", "cd" * 32) not in ledger._records


def test_no_appending_to_a_broken_log(tmp_path):
    path = tmp_path / "log.jsonl"
    p, _ = writer(path, 1)
    with open(path, "a") as f:
        f.write("garbage\n")
    with pytest.raises(PlugError) as e:
        p.prove("more", "doc.sha256")
    assert e.value.code == "proof_invalid" and "broken" in e.value.message


def test_a_partly_written_last_line_is_not_read_yet(tmp_path):
    path = tmp_path / "log.jsonl"
    _, atts = writer(path, 1)
    with open(path, "a") as f:
        f.write('{"network": "log"')
    assert reader(path).check(atts[0])["valid"] is True


def _write_many(path, n):
    writer(path, n)


def test_processes_share_one_log(tmp_path):
    path = tmp_path / "log.jsonl"
    ctx = multiprocessing.get_context("spawn")
    procs = [ctx.Process(target=_write_many, args=(str(path), 10)) for _ in range(4)]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(60)
        assert proc.exitcode == 0
    ledger = LocalLedger(str(path))
    assert ledger._broken is None and ledger.head()["seq"] == 39


def _next_record(path, **fields):
    recs = lines(path)
    rec = {"network": "log", "statement_hash": "cd" * 32, "subject_hash": "ef" * 32, "issuer": recs[-1]["issuer"],
           "anchored_at": recs[-1]["anchored_at"], "seq": len(recs), "prev": sha256_hex(canonical(recs[-1]))}
    rec.update(fields)
    return rec


@pytest.mark.parametrize("line", [
    '{"anchored_at": "2026-01-01T00:00:00Z", "issuer": "\\ud800", "network": "log", "prev": "PREV", "seq": SEQ, '
    '"statement_hash": "STMT", "subject_hash": "ef"}',
    "[" * 100000 + "]" * 100000,
])
def test_records_canonical_form_refuses_break_the_chain_and_never_verify(tmp_path, line):
    path = tmp_path / "log.jsonl"
    _, atts = writer(path, 1)
    target = Attestation.from_receipt(writer(tmp_path / "other.jsonl", 1)[0].prove("forged", "doc.sha256"))
    recs = lines(path)
    line = line.replace("PREV", sha256_hex(canonical(recs[-1]))).replace("SEQ", "1")
    line = line.replace("STMT", __import__("upp").statement_hash(target))
    with open(path, "a") as f:
        f.write(line + "\n")
    q = reader(path)
    for _ in range(2):  # the second check must not see a half-accepted record either
        v = q.check(target, "log")
        assert v["valid"] is False and "chain breaks" in v["receipt"].error
    assert q.check(atts[0])["valid"] is True and LocalLedger(str(path)).head()["seq"] == 0


def keeper_plug(path, keeper):
    p = Plug(trust={"log": ANY})
    p.register("log", LocalLedger(str(path), keeper=keeper))
    p.open("log")
    return p


def test_a_keeper_signs_every_record_and_readers_require_it(tmp_path):
    from upp.suites import KeySigner, generate_key
    path, keeper = tmp_path / "log.jsonl", KeySigner("ed25519", generate_key("ed25519"))
    p = keeper_plug(path, keeper)
    atts = [Attestation.from_receipt(p.prove(f"fact {i}", "doc.sha256")) for i in range(2)]
    assert all("keeper_proof" in r for r in lines(path))
    strict = Plug(trust={"log": ANY})
    strict.register("log", LocalLedger(str(path), keeper=keeper.verification_method))
    assert all(strict.check(a)["valid"] for a in atts)
    assert all(reader(path).check(a)["valid"] for a in atts)  # a reader without a keeper still reads it


def test_without_the_keeper_key_a_well_chained_record_is_refused(tmp_path):
    from upp.suites import KeySigner, generate_key
    path, keeper = tmp_path / "log.jsonl", KeySigner("ed25519", generate_key("ed25519"))
    keeper_plug(path, keeper).prove("genuine", "doc.sha256")
    stolen = Plug(trust={"log": ANY})  # someone with a valid issuer key and write access to the file
    stolen.register("log", LocalLedger(str(tmp_path / "scratch.jsonl")))
    stolen.open("log")
    forged = Attestation.from_receipt(stolen.prove("backdated", "doc.sha256"))
    from upp import statement_hash
    with open(path, "a") as f:
        f.write(canonical(_next_record(path, statement_hash=statement_hash(forged), issuer=forged.issuer)) + "\n")
    strict = Plug(trust={"log": ANY})
    strict.register("log", LocalLedger(str(path), keeper=keeper.verification_method))
    v = strict.check(forged, "log")
    assert v["valid"] is False and "not signed by the log keeper" in v["receipt"].error


def test_a_reader_that_only_knows_the_keeper_cannot_append(tmp_path):
    from upp.suites import KeySigner, generate_key
    keeper = KeySigner("ed25519", generate_key("ed25519"))
    p = keeper_plug(tmp_path / "log.jsonl", keeper.verification_method)
    with pytest.raises(PlugError) as e:
        p.prove("x", "doc.sha256")
    assert e.value.code == "auth_failed"
    with pytest.raises(ValueError):
        LocalLedger(keeper="0x" + "11" * 20)
