# Direct-mode unit tests for SafeSignal.  Run: pytest tests/direct/ -v
import json

CONTRACT = "contracts/safesignal.py"


def test_submit_and_analyze(direct_vm, direct_deploy, direct_alice):
    c = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    idx = c.submit_url("https://login-update-account.example.com")
    assert int(idx) == 0

    direct_vm.mock_web(r".*example\.com.*", {
        "status": 200,
        "body": "Verify your account NOW or it will be suspended. Enter your password and seed phrase.",
    })
    direct_vm.mock_llm(r".*security analyst.*", json.dumps(
        {"classification": "malicious", "risk": 95, "reasoning": "credential phishing with urgency"}
    ))
    c.analyze(0)

    chk = c.get_check(0)
    assert chk["classification"] == "malicious"
    assert int(chk["risk"]) == 95
    assert bool(chk["analyzed"]) is True

    info = c.get_info()
    assert int(info["malicious"]) == 1


def test_submit_rejects_bad_url(direct_vm, direct_deploy, direct_alice):
    c = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("must start with"):
        c.submit_url("javascript:alert(1)")


def test_analyze_rejects_invalid_id(direct_vm, direct_deploy, direct_alice):
    c = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("invalid check id"):
        c.analyze(0)


def test_validator_rejects_divergent_class(direct_vm, direct_deploy, direct_alice):
    c = direct_deploy(CONTRACT)
    direct_vm.sender = direct_alice
    c.submit_url("https://example.com/page")
    direct_vm.mock_web(r".*example\.com.*", {"status": 200, "body": "normal blog post"})
    direct_vm.mock_llm(r".*security analyst.*", json.dumps({"classification": "safe", "risk": 5, "reasoning": "ok"}))
    c.analyze(0)
    # A validator reaching a different classification must disagree.
    direct_vm.mock_llm(r".*security analyst.*", json.dumps({"classification": "malicious", "risk": 90, "reasoning": "no"}))
    assert direct_vm.run_validator() is False
