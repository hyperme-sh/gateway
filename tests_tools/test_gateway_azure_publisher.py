import base64
import io
import json
from pathlib import Path
import re
from textwrap import dedent

import pytest


WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def test_dispatch_defaults_to_verification_and_passes_the_exact_mode():
    caller = (WORKFLOWS / "dispatch-azure-runtime.yml").read_text()
    assert re.search(r"verify_identity_only:\n(?: {8}[^\n]+\n)* {8}default: true", caller)
    assert "uses: ./.github/workflows/publish-azure-runtime.yml" in caller
    assert "verify_identity_only: ${{ inputs.verify_identity_only }}" in caller


def test_registry_publisher_uses_the_existing_release_runner_policy():
    registry = (WORKFLOWS / "publish-azure-runtime.yml").read_text()
    stable = (WORKFLOWS / "release-publish.yml").read_text()
    find_runner = r"^    runs-on: .*$"
    assert re.findall(find_runner, registry, re.M) == re.findall(find_runner, stable, re.M)
    assert len(re.findall(find_runner, registry, re.M)) == 1


@pytest.mark.parametrize("verify_only", (True, False))
def test_only_publication_mode_reaches_azure_and_the_registries(verify_only):
    workflow = (WORKFLOWS / "publish-azure-runtime.yml").read_text()
    assert "workflow_call:" in workflow
    steps = re.split(r"^      - ", workflow, flags=re.M)[1:]
    guard = "if: ${{ !inputs.verify_identity_only }}"
    assert len(steps) == 5
    assert steps[0].startswith("name: Verify the actual GitHub OIDC claims")
    assert "if:" not in steps[0]
    assert steps[1].startswith("name: Verify the immutable release")
    assert steps[2].startswith("uses: azure/login@")
    assert steps[3].startswith("name: Mirror the qualified bytes")
    assert all(guard in step for step in steps[1:4])
    assert steps[4].startswith("name: Remove job-local registry credentials")
    selected = [step for step in steps if guard not in step or not verify_only]
    assert selected == ([steps[0], steps[4]] if verify_only else steps)


def test_claim_check_discloses_only_expected_claims(monkeypatch, tmp_path):
    workflow = (WORKFLOWS / "publish-azure-runtime.yml").read_text()
    source = workflow.split("python3 - <<'PY'\n", 1)[1].split("\n          PY", 1)[0]
    prefix = "hyperme-sh/gateway/.github/workflows/"
    claims = {
        "iss": "https://token.actions.githubusercontent.com", "aud": "api://AzureADTokenExchange",
        "event_name": "workflow_dispatch", "repository": "hyperme-sh/gateway",
        "repository_id": "1439103692", "repository_owner_id": "351507761", "ref": "refs/heads/main",
        "sub": "repo:hyperme-sh@351507761/gateway@1439103692:ref:refs/heads/main",
        "job_workflow_ref": prefix + "publish-azure-runtime.yml@refs/heads/main",
        "workflow_ref": prefix + "dispatch-azure-runtime.yml@refs/heads/main",
        "jti": "excluded-fixture-value",
    }
    summary = tmp_path / "summary"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://example.test/issuer?api-version=1")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "fixture-request-token")

    def issue(request, timeout):
        assert request.get_header("Authorization") == "Bearer fixture-request-token"
        assert "audience=api%3A%2F%2FAzureADTokenExchange" in request.full_url
        assert timeout == 20
        payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
        return io.BytesIO(json.dumps({"value": f"header.{payload}.signature"}).encode())

    monkeypatch.setattr("urllib.request.urlopen", issue)
    compiled = compile(dedent(source), "gateway-azure-identity", "exec")
    exec(compiled, {})
    recorded = summary.read_text()
    assert "excluded-fixture-value" not in recorded and "fixture-request-token" not in recorded
    del claims["job_workflow_ref"]
    with pytest.raises(SystemExit, match="differs from the dedicated Gateway publisher trust"):
        exec(compiled, {})
