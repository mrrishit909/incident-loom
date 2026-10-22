from harness.intake import decide
from harness.issueform import sections

BODY = """### Event batches

- [X] 2026-10-13
- [X] 2026-10-14
- [X] 2026-10-15
- [ ] 2026-10-16
- [ ] 2026-10-17
- [ ] 2026-10-18

### Clock-skew correction

on

### Simulate a restart after batch

2
"""


def event(action="opened", author="mrrishit909", sender=None, body=BODY, labels=("type:run",), label=None):
    ev = {
        "action": action,
        "repository": {"owner": {"login": "mrrishit909"}},
        "sender": {"login": sender or author},
        "issue": {"number": 7, "state": "open", "user": {"login": author}, "body": body,
                  "labels": [{"name": n} for n in labels]},
    }
    if label:
        ev["label"] = {"name": label}
    return ev


def test_sections_handles_no_response():
    assert sections("### A\n\n_No response_\n") == {"A": None}


def test_owner_request_dispatches_exact_params():
    d = decide(event())
    assert d["action"] == "dispatch"
    assert d["params"] == {"batches": ["2026-10-13", "2026-10-14", "2026-10-15"], "clock_skew_correction": "on",
                           "simulate_restart_after": 2}


def test_non_owner_blocked_regardless_of_labels():
    assert decide(event(author="someone", labels=("type:run", "job:approved")))["action"] == "blocked"


def test_approval_only_from_owner():
    assert decide(event(action="labeled", author="x", sender="x", label="job:approved"))["action"] == "blocked"
    assert decide(event(action="labeled", author="x", sender="mrrishit909", label="job:approved"))["action"] == "dispatch"


def test_injection_in_free_text_is_rejected():
    d = decide(event(body=BODY.replace("\non\n", "\non; rm -rf /\n")))
    assert d["action"] == "invalid" and all("rm -rf" not in e for e in d["errors"])


def test_restart_after_last_batch_is_invalid():
    d = decide(event(body=BODY.replace("\n2\n", "\n3\n")))
    assert d["action"] == "invalid"


def test_no_batch_selected_is_invalid():
    d = decide(event(body=BODY.replace("[X]", "[ ]")))
    assert d["action"] == "invalid"


def test_ignores_issues_without_run_label():
    assert decide(event(labels=()))["action"] == "ignore"
