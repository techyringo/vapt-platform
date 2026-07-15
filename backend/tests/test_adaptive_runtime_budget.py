from tools.runner import adaptive_timeout_seconds


def test_arjun_budget_scales_with_endpoint_batch(tmp_path, monkeypatch):
    monkeypatch.setenv("VAPT_ADAPTIVE_TOOL_TIMEOUTS", "true")
    target_list = tmp_path / "targets.txt"
    target_list.write_text("\n".join(f"https://example.test/{i}" for i in range(6)))

    assert adaptive_timeout_seconds("arjun", 180, ["-i", str(target_list)]) == 405


def test_adaptive_budget_obeys_global_safety_ceiling(tmp_path, monkeypatch):
    monkeypatch.setenv("VAPT_ADAPTIVE_TOOL_TIMEOUTS", "true")
    monkeypatch.setenv("VAPT_TOOL_MAX_RUNTIME", "300")
    target_list = tmp_path / "targets.txt"
    target_list.write_text("\n".join(f"host-{i}.test" for i in range(100)))

    assert adaptive_timeout_seconds("nmap", 180, ["-iL", str(target_list)]) == 300


def test_adaptive_budget_can_be_disabled(monkeypatch):
    monkeypatch.setenv("VAPT_ADAPTIVE_TOOL_TIMEOUTS", "false")

    assert adaptive_timeout_seconds("waybackurls", 90, ["example.test"]) == 90


def test_caller_deadline_caps_adaptive_budget(tmp_path, monkeypatch):
    monkeypatch.setenv("VAPT_ADAPTIVE_TOOL_TIMEOUTS", "true")
    target_list = tmp_path / "targets.txt"
    target_list.write_text("\n".join(f"https://example.test/{i}" for i in range(100)))

    assert adaptive_timeout_seconds(
        "nuclei", 300, ["-l", str(target_list)], hard_cap=420,
    ) == 420
