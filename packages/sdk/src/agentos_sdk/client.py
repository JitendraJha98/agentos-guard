"""SDK-02/04 — the control-plane client. A thin httpx wrapper that carries the shared API token as a
Bearer header; register() self-registers an agent and returns its identity token; the rest is
resource CRUD + approvals over the declarative API. Decoupled from the control plane internals — pure
HTTP, depends only on httpx."""
from __future__ import annotations

import httpx


class ControlPlaneError(Exception):
    """A non-2xx control-plane response (status + body)."""


class ControlPlaneClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._http = httpx.Client(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}"},
            transport=transport,  # tests inject httpx.ASGITransport(app=app)
            timeout=timeout,
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "ControlPlaneClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _request(self, method: str, path: str, **kw):
        resp = self._http.request(method, path, **kw)
        if resp.status_code >= 400:
            raise ControlPlaneError(f"{method} {path} -> {resp.status_code}: {resp.text}")
        return resp.json() if resp.content else None

    # ---- SDK-02 self-registration ----
    def register(self, agent_id: str, *, manifest: dict | None = None) -> str:
        # No trust_score: registration is not a self-grading channel (the server seeds the default
        # trust). Trust is graded only via the gated put_trust_profile() operator path.
        body: dict = {}
        if manifest is not None:
            body["manifest"] = manifest
        return self._request("POST", f"/agents/{agent_id}/register", json=body)["token"]

    # ---- approvals (SDK-04) ----
    def list_approvals(self, status: str | None = None) -> list[dict]:
        return self._request("GET", "/approvals", params={"status": status} if status else None)

    def resolve_approval(
        self, approval_id: str, *, approved: bool, resolver: str, note: str | None = None
    ) -> dict:
        body: dict = {"approved": approved, "resolver": resolver}
        if note is not None:
            body["note"] = note
        return self._request("POST", f"/approvals/{approval_id}/resolve", json=body)

    # ---- resources (SDK-04) ----
    def put_trust_profile(
        self,
        agent_id: str,
        *,
        trust_score: float,
        band: dict | None = None,
        version: int | None = None,
    ) -> dict:
        return self._request(
            "PUT",
            f"/trust-profiles/{agent_id}",
            json={"trust_score": trust_score, "band": band, "version": version},
        )

    def get_trust_profile(self, agent_id: str) -> dict:
        return self._request("GET", f"/trust-profiles/{agent_id}")

    def list_trust_profiles(self) -> list[dict]:
        return self._request("GET", "/trust-profiles")

    def put_abom(self, agent_id: str, *, components: dict, version: int | None = None) -> dict:
        return self._request(
            "PUT", f"/aboms/{agent_id}", json={"components": components, "version": version}
        )

    def apply_constitution(self, name: str, source: dict) -> dict:
        return self._request("POST", "/constitutions", json={"name": name, "source": source})

    def get_latest_policy(self) -> dict:
        return self._request("GET", "/policies/latest")

    def list_inventory(self) -> list[dict]:
        return self._request("GET", "/inventory")

    def get_inventory(self, agent_id: str) -> list[dict]:
        return self._request("GET", f"/inventory/{agent_id}")
