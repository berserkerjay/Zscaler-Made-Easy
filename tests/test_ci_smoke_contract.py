"""The workflow's exact production smoke script remains offline and meaningful."""
from pathlib import Path
import textwrap


def test_ci_smoke_reaches_disabled_write_gate_without_a_tenant(monkeypatch):
    import dlp_api_server as srv
    import security
    monkeypatch.delenv("ENABLE_WRITE_ACTIONS", raising=False)
    monkeypatch.setattr(security, "_write_override", None)

    def no_tenant(*args, **kwargs):
        raise AssertionError("The CI smoke must never construct a tenant client")

    monkeypatch.setattr(srv, "_build_sdk_client", no_tenant)
    monkeypatch.setattr(srv, "_build_client", no_tenant)
    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/tests.yml").read_text()
    section = workflow.split("- name: Smoke-test API server and Deploy Studio injection", 1)[1]
    source = section.split("python - <<'EOF'\n", 1)[1].split("\n          EOF", 1)[0]
    source = textwrap.dedent(source)
    assert '"assessor": "Synthetic CI Assessor"' in source
    assert "assert r.status_code == 403" in source
    exec(compile(source, "tests.yml:api-smoke", "exec"), {})
