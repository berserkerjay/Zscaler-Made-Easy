# Working with the Zscaler SDK

- The app uses the installed **zscaler-sdk-python** (pinned in `requirements.lock`; the code lives in the venv's `site-packages/zscaler/`). Before using any service, method, path, model or field, open it there and confirm it. If you can't confirm a detail (a raw path, an enum value, a field the model drops), mark it `# assumed:` in a code comment, list it in your stage output, and add it to `references/assumed.md`.
- Clients: OneAPI SDK client via `sdk_client.py`; the classic ZIA session (`tenant_auth.py`); offline client for the sample tenant and snapshots (`offline_tenant.py`). Rate limits and waits: `zia_rate.py`. Every call is logged by path template in the API-calls ring buffer (`api_calls.py`).
- Models sometimes drop fields the API returns (e.g. scopes, secrets lists, some device fields). Read the raw answer when the model loses data you need; never log it.
- **Raw calls outside the SDK** (an endpoint the SDK lacks): allowed only for reads or for writes that go through the engine; build the path from fixed parts; mark the endpoint assumed unless verified against Zscaler's public API documentation.
- Semantics to respect: ZIA rules are evaluated by order (admin rank first when Admin Ranking is on, `admin_rank.py`), default rule last; ZIA changes need activation; ZPA policy is first-match by rule order with default deny; PUTs replace whole objects.
- Terraform providers: `zscaler/zia`, `zscaler/zpa`, `zscaler/ztc`, `zscaler/zcc` (beta, pin the exact version; OneAPI only; not for zscalergov/zscalerten).
