"""The Content-Security-Policy, and the one script it admits by name.

A CSP carrying `'unsafe-inline'` leaves open exactly the door it exists to
close: an injected inline script runs anyway. These tests are the claim that
the policy is worth the header it is sent in.
"""
import re


def _csp(response) -> str:
    return response.headers["content-security-policy"]


def test_the_policy_forbids_inline_script_and_style(client):
    csp = _csp(client.get("/app"))

    assert "'unsafe-inline'" not in csp
    assert "'unsafe-eval'" not in csp


def test_the_policy_names_the_expected_directives(client):
    csp = _csp(client.get("/app"))

    for directive in (
        "default-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ):
        assert directive in csp, directive


def test_every_response_carries_a_fresh_nonce(client):
    """A nonce reused across responses is a nonce an attacker can learn."""
    first = re.search(r"'nonce-([^']+)'", _csp(client.get("/app"))).group(1)
    second = re.search(r"'nonce-([^']+)'", _csp(client.get("/app"))).group(1)

    assert first != second
    assert len(first) >= 16


def test_the_interface_loads_its_script_and_style_from_files(client):
    """Nothing inline is left in the page, which is what lets the policy be strict."""
    html = client.get("/app").text

    assert '<script src="/static/app.js"' in html
    assert '<link rel="stylesheet" href="/static/app.css">' in html
    assert "<style>" not in html
    # The only <script> tag is the external one.
    assert len(re.findall(r"<script\b", html)) == 1


def test_the_static_files_are_served(client):
    for path in ("/static/app.js", "/static/app.css"):
        assert client.get(path).status_code == 200, path


def test_no_inline_style_attributes_survive_in_the_page(client):
    """`style="…"` is inline style too, and `style-src 'self'` blocks it."""
    html = client.get("/app").text

    assert not re.search(r'<[a-zA-Z][^>]*\sstyle="', html)


def test_no_inline_event_handlers_survive_in_the_page(client):
    """onclick="…" is an inline script by another name."""
    html = client.get("/app").text

    assert not re.search(r'\son(click|load|error|change|submit)="', html)
