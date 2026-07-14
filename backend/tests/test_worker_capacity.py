from worker.settings import _effective_max_jobs


def test_stale_worker_concurrency_is_capped(monkeypatch) -> None:
    monkeypatch.setenv("WORKER_MAX_JOBS", "3")
    monkeypatch.setenv("WORKER_MAX_JOBS_HARD_LIMIT", "2")

    assert _effective_max_jobs() == (3, 2, 2)
