/* Bounded orchestration helpers, independently tested without launching Chrome. */
export async function waitForDebugger({readActivePort, readTargets, hasExited, diagnostic = () => '', now = Date.now, sleep, timeoutMs = 30000}) {
  const deadline = now() + timeoutMs;
  let last = 'No DevToolsActivePort file';
  while (now() < deadline) {
    if (hasExited()) throw new Error('Chrome exited before CDP readiness: ' + diagnostic());
    try {
      const line = String(await readActivePort()).split(/\r?\n/)[0];
      const port = /^\d+$/.test(line) ? Number(line) : 0;
      if (port > 0 && port < 65536) {
        const targets = await readTargets(port);
        const target = Array.isArray(targets) && targets.find(item => item.type === 'page' && item.webSocketDebuggerUrl);
        if (target) {
          const endpoint = new URL(target.webSocketDebuggerUrl);
          if (endpoint.protocol !== 'ws:' || !['127.0.0.1', 'localhost', '[::1]'].includes(endpoint.hostname) || Number(endpoint.port) !== port) throw new Error('CDP target was not on the expected loopback endpoint');
          return {port, target};
        }
        last = 'CDP HTTP is ready but no page target is available';
      } else last = 'DevToolsActivePort is incomplete or malformed';
    } catch (error) {
      if (error.message === 'CDP target was not on the expected loopback endpoint') throw error;
      last = error.message;
    }
    await sleep(100);
  }
  throw new Error(`Chrome did not expose a ready CDP page within ${timeoutMs} ms; last=${last}; ${diagnostic()}`);
}

export async function waitForStablePoint(sample, {now = Date.now, sleep, timeoutMs = 4000} = {}) {
  const deadline = now() + timeoutMs;
  let previous = null, last = null;
  while (now() < deadline) {
    last = await sample();
    if (last && last.ready && Number.isFinite(last.x) && Number.isFinite(last.y)) {
      if (previous && Math.abs(last.x - previous.x) <= .5 && Math.abs(last.y - previous.y) <= .5) return last;
      previous = last;
    } else previous = null;
    await sleep(75);
  }
  throw new Error('Native click target never became stable, enabled and hit-testable: ' + JSON.stringify(last));
}
