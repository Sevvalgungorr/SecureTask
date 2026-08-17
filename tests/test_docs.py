"""The API docs must not depend on anything off this host.

FastAPI's stock page loads Swagger UI from a public CDN, which this
application's own Content-Security-Policy forbids — so it rendered blank and
nobody noticed until someone opened it. This is the regression guard.
"""
import re


def test_docs_page_renders(client):
    response = client.get("/docs")
    assert response.status_code == 200
    assert "swagger-ui" in response.text


def test_the_docs_bootstrap_script_carries_the_nonce(client):
    """The page has one inline script — the call that starts Swagger UI.

    Returning the page is not the same as the page working: under a policy
    without 'unsafe-inline' an inline script with no nonce is blocked and the
    page renders blank. That is what happened once, and what the test above
    could not see.
    """
    response = client.get("/docs")
    nonce = re.search(r"'nonce-([^']+)'", response.headers["content-security-policy"]).group(1)

    assert f'<script nonce="{nonce}">' in response.text
    # And no inline script without one.
    assert "<script>" not in response.text


def test_docs_page_references_no_external_host(client):
    """A third-party script host on the page that renders the whole API surface
    is exactly the supply-chain risk this application exists to track."""
    html = client.get("/docs").text
    external = [
        url for url in re.findall(r'(?:src|href)="([^"]+)"', html)
        if url.startswith("http://") or url.startswith("https://")
    ]
    assert external == []


def test_the_vendored_assets_are_actually_served(client):
    for path in (
        "/static/vendor/swagger-ui-bundle.js",
        "/static/vendor/swagger-ui.css",
        "/static/vendor/favicon.svg",
    ):
        assert client.get(path).status_code == 200, path


def test_the_openapi_schema_is_reachable(client):
    body = client.get("/openapi.json").json()
    assert body["info"]["title"] == "SecureTask"
    assert "/findings" in body["paths"]
