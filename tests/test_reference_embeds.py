"""Reference fix acceptance matrix.

Each case is a separately named behavior, not a repeated execution. Browser
layout/CSP enforcement still requires a real-browser acceptance run; these
HTTP, content, and production-controller tests do not claim that coverage.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess

import pytest
from fastapi.testclient import TestClient
import dlp_api_server as srv
import security

ROOT = Path(__file__).resolve().parents[1]
SLUGS = ['portfolio-map', 'copilot-readiness']
TITLES = {'portfolio-map': 'Zscaler Data Security — Portfolio Map',
          'copilot-readiness': 'Microsoft 365 Copilot Readiness Framework'}
# These case IDs are the HTTP/content part of the per-request coverage matrix.
CONTRACTS = [
    'served', 'html-content-type', 'correct-title', 'same-origin-framing',
    'same-origin-ancestors', 'canonical-csp-preserved', 'no-blob-permission',
    'cache-revalidation', 'nosniff', 'no-referrer', 'permissions-preserved',
    'one-child-bridge', 'bridge-before-page-scripts', 'charset-precedes-bridge',
    'correct-bridge-identity', 'query-never-injected-as-html', 'query-does-not-select-file',
    'unknown-suffix-denied', 'filename-url-denied', 'case-sensitive-allowlist',
    'unlisted-document-denied', 'traversal-denied', 'missing-asset-is-404',
    'parent-framing-still-denied', 'static-direct-framing-still-denied',
    'authentication-required', 'authenticated-cookie-supported',
    'bridge-script-served', 'loader-script-served', 'parent-loads-shared-controller',
    'parent-retry-control', 'parent-status-announcement', 'parent-iframe-accessibility',
    'no-external-embedded-resources', 'no-external-font-imports',
    'no-blob-frame-loader', 'document-structure-and-controls-preserved',
    'scripts-parse', 'reference-list-unchanged', 'content-handshake-prerequisites',
]

@pytest.fixture(scope='module')
def client():
    return TestClient(srv.app)

@pytest.fixture(scope='module')
def responses(client):
    return {slug: client.get('/reference/embed/' + slug) for slug in SLUGS}

@pytest.mark.parametrize('slug', SLUGS)
@pytest.mark.parametrize('contract', CONTRACTS)
def test_embed_response_contract(slug, contract, client, responses, monkeypatch, tmp_path):
    response = responses[slug]
    html = response.text
    headers = response.headers
    parent = (ROOT / 'static/reference/data-security-portfolio-framework.html').read_text()
    frame = 'mapFrame' if slug == 'portfolio-map' else 'copilotFrame'
    bridge = '/static/reference/reference_embed_child.js'
    if contract == 'served':
        assert response.status_code == 200
    elif contract == 'html-content-type':
        assert headers['content-type'].startswith('text/html; charset=utf-8')
    elif contract == 'correct-title':
        assert f'<title>{TITLES[slug]}</title>' in html
    elif contract == 'same-origin-framing':
        assert headers['x-frame-options'] == 'SAMEORIGIN'
    elif contract == 'same-origin-ancestors':
        assert "frame-ancestors 'self'" in headers['content-security-policy']
        assert "frame-ancestors 'none'" not in headers['content-security-policy']
    elif contract == 'canonical-csp-preserved':
        assert headers['content-security-policy'] == security.CONTENT_SECURITY_POLICY.replace("frame-ancestors 'none'", "frame-ancestors 'self'")
    elif contract == 'no-blob-permission':
        assert 'blob:' not in headers['content-security-policy']
        assert "default-src 'self'" in headers['content-security-policy']
    elif contract == 'cache-revalidation':
        assert headers['cache-control'] == 'no-cache, must-revalidate, max-age=0'
    elif contract == 'nosniff':
        assert headers['x-content-type-options'] == 'nosniff'
    elif contract == 'no-referrer':
        assert headers['referrer-policy'] == 'no-referrer'
    elif contract == 'permissions-preserved':
        assert headers['permissions-policy'] == 'camera=(), microphone=(), geolocation=(), usb=()'
    elif contract == 'one-child-bridge':
        assert html.count(f'<script src="{bridge}"></script>') == 1
    elif contract == 'bridge-before-page-scripts':
        assert html.index(bridge) < html.index('<script>', html.index(bridge))
    elif contract == 'charset-precedes-bridge':
        assert re.search(r'<meta\s+charset=[^>]+>', html, re.I).end() < html.index(bridge)
    elif contract == 'correct-bridge-identity':
        assert html.count(f'<meta name="dlp-reference-embed" content="{slug}">') == 1
    elif contract == 'query-never-injected-as-html':
        r = client.get('/reference/embed/'+slug, params={'embed_token':'"><script>alert(1)</script>'})
        assert r.status_code == 200 and r.text == html
    elif contract == 'query-does-not-select-file':
        r = client.get('/reference/embed/'+slug, params={'path':'../../security.py','slug':'../index'})
        assert r.status_code == 200 and r.text == html
    elif contract == 'unknown-suffix-denied':
        assert client.get('/reference/embed/'+slug+'-unknown').status_code == 404
    elif contract == 'filename-url-denied':
        assert client.get('/reference/embed/'+slug+'.html').status_code == 404
    elif contract == 'case-sensitive-allowlist':
        assert client.get('/reference/embed/'+slug.upper()).status_code == 404
    elif contract == 'unlisted-document-denied':
        assert client.get('/reference/embed/'+slug+'/security.py').status_code == 404
    elif contract == 'traversal-denied':
        assert client.get('/reference/embed/'+slug+'/%2e%2e/%2e%2e/security.py').status_code in (400,404)
    elif contract == 'missing-asset-is-404':
        monkeypatch.setattr(srv, '_REFERENCE_DIR', str(tmp_path))
        r=client.get('/reference/embed/'+slug)
        assert r.status_code == 404 and 'Embedded reference missing' in r.text
        assert r.headers['x-frame-options'] == 'DENY'
    elif contract == 'parent-framing-still-denied':
        r=client.get('/reference/data-security-portfolio-framework')
        assert r.headers['x-frame-options']=='DENY'
        assert r.headers['content-security-policy']==security.CONTENT_SECURITY_POLICY
    elif contract == 'static-direct-framing-still-denied':
        r=client.get('/static/reference/'+slug+'.html')
        assert r.status_code==200 and r.headers['x-frame-options']=='DENY'
        assert "frame-ancestors 'none'" in r.headers['content-security-policy']
    elif contract == 'authentication-required':
        monkeypatch.setenv('ZSCALER_UI_AUTH','1')
        r=TestClient(srv.app).get('/reference/embed/'+slug)
        assert r.status_code==401 and r.json()['token_required'] is True
    elif contract == 'authenticated-cookie-supported':
        monkeypatch.setenv('ZSCALER_UI_AUTH','1')
        monkeypatch.setattr(security, 'ui_token', lambda:'reference-test-only')
        c=TestClient(srv.app);c.cookies.set(security.UI_TOKEN_COOKIE, 'reference-test-only')
        assert c.get('/reference/embed/'+slug).status_code==200
    elif contract == 'bridge-script-served':
        r=client.get(bridge)
        assert r.status_code==200 and 'dlp-reference-state' in r.text
        assert r.headers['x-frame-options']=='DENY'
    elif contract == 'loader-script-served':
        r=client.get('/static/reference/reference_embeds.js')
        assert r.status_code==200 and 'createController' in r.text
    elif contract == 'parent-loads-shared-controller':
        assert parent.count('<script src="/static/reference/reference_embeds.js"></script>')==1
        assert f"window.ReferenceEmbeds.open('{slug}')" in parent
    elif contract == 'parent-retry-control':
        assert re.search(fr'<button[^>]+id="{frame}Retry"[^>]*hidden',parent)
    elif contract == 'parent-status-announcement':
        assert re.search(fr'<div[^>]+id="{frame}Status"[^>]+role="status"[^>]+aria-live="polite"',parent)
    elif contract == 'parent-iframe-accessibility':
        assert re.search(fr'<iframe[^>]+id="{frame}"[^>]+aria-describedby="{frame}Status"[^>]+title="[^"]+"',parent)
    elif contract == 'no-external-embedded-resources':
        assert not re.search(r'<(?:script|link|img|iframe)[^>]+(?:src|href)=[\'\"]https?://',html)
    elif contract == 'no-external-font-imports':
        assert 'fonts.googleapis.com' not in html and 'fonts.gstatic.com' not in html
    elif contract == 'no-blob-frame-loader':
        assert 'f.src = URL.createObjectURL' not in parent
        assert 'PORTFOLIO_MAP_B64' not in parent and 'COPILOT_FRAMEWORK_B64' not in parent
    elif contract == 'document-structure-and-controls-preserved':
        if slug=='portfolio-map':
            for key in ['chains','channels','dictionary','edmidm','engine','evalall','access','aisec','endpoint','email','saas','sspm','dspm','workflow','setup','troubleshoot','learn','learnsales','learnai']:
                assert f'id="{key}"' in html
            assert '__mapShow' in html and 'dlPng' in html and 'dlSvg' in html
            assert 'data:image/svg+xml;charset=utf-8,' in html
        else:
            for key in ['tab-framework','tab-playbook','tab-proposal','tab-pov','matrix','channelToggles','povPreview']:
                assert f'id="{key}"' in html
            assert 'POV_BASELINE_CATALOG_CSV' in html and 'exportPovPPTX' in html
    elif contract == 'scripts-parse':
        scripts=re.findall(r'<script>(.*?)</script>',html,re.S)
        assert len(scripts)==(3 if slug=='portfolio-map' else 1)
        for script in scripts:
            result=subprocess.run(['node','--check'],input=script,text=True,capture_output=True)
            assert result.returncode==0,result.stderr
    elif contract == 'reference-list-unchanged':
        r=client.get('/api/reference').json()['pages']
        assert len(r)==5 and all(p['slug'] not in SLUGS for p in r)
    elif contract == 'content-handshake-prerequisites':
        if slug=='portfolio-map':
            assert 'nav.sections' in html and 'window.__mapShow = show' in html
            assert 'show(initial||"chains")' in html
        else:
            assert 'function switchTab(' in html and 'function renderMatrix(' in html
            assert 'ensurePovCatalogLoaded();\nrenderMatrix();' in html
    else:
        raise AssertionError('Unimplemented contract: '+contract)

# Execute the production JS lifecycle once and expose every distinct named
# behavior as a pytest case with an inspectable ID.
@pytest.fixture(scope='module')
def js_results():
    p=subprocess.run(['node',str(ROOT/'tests/js/reference_embeds_cases.cjs')],text=True,capture_output=True,cwd=ROOT)
    results=json.loads(p.stdout)
    assert results and len({r['id'] for r in results})==len(results)
    return {r['id']:r for r in results}

# Case discovery is read-only; it does not require a browser or application.
_DISCOVER = json.loads(subprocess.run(['node',str(ROOT/'tests/js/reference_embeds_cases.cjs'),'--list'],text=True,capture_output=True,cwd=ROOT,check=True).stdout)
@pytest.mark.parametrize('case_id',[r['id'] for r in _DISCOVER])
def test_embed_controller_behavior(case_id,js_results):
    result=js_results[case_id]
    assert result['pass'],result.get('error')

@pytest.fixture(scope='module')
def document_script_results():
    p=subprocess.run(['node',str(ROOT/'tests/js/reference_document_cases.cjs')],text=True,capture_output=True,cwd=ROOT)
    result=json.loads(p.stdout)
    assert result and len({r['id'] for r in result})==len(result)
    return result

@pytest.mark.parametrize('slug',SLUGS)
def test_reference_document_script_behaviors(slug,document_script_results):
    relevant=[r for r in document_script_results if r['id'].startswith(slug+'/')]
    assert len(relevant)>=17
    failures=[r for r in relevant if not r['pass']]
    assert not failures,failures
