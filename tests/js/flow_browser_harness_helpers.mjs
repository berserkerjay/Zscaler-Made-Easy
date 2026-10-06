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

export async function waitForStablePoint(sample, {now = Date.now, sleep, timeoutMs = 4000, reveal = null} = {}) {
  const deadline = now() + timeoutMs;
  let previous = null, last = null;
  while (now() < deadline) {
    last = await sample();
    // Navigation can finish a pending smooth scroll after the caller first
    // revealed its target. Re-reveal only an off-viewport, enabled, visible
    // target, then require fresh stable geometry and normal hit-testing.
    // An overlay, hidden/disabled control or permanently displaced target
    // still fails within the original deadline; this never dispatches clicks.
    if (last && last.offscreen === true && !last.hidden && !last.disabled && typeof reveal === 'function') {
      previous = null;
      await reveal();
    } else if (last && last.ready && !last.offscreen && Number.isFinite(last.x) && Number.isFinite(last.y)) {
      if (previous && last.targetId === previous.targetId && Math.abs(last.x - previous.x) <= .5 && Math.abs(last.y - previous.y) <= .5) return last;
      previous = last;
    } else previous = null;
    await sleep(75);
  }
  throw new Error('Native click target never became stable, enabled and hit-testable: ' + JSON.stringify(last));
}

// A document listener survives controls being replaced during preparation.
// Only a trusted click on the current intended selector is a receipt; native
// down/up events are diagnostic evidence, never a substitute for that click.
export function installNativeClickProbe(doc, store, selector, token) {
  if (!store.identify) {
    const nodes = new WeakMap(); let sequence = 0;
    store.identify = node => {
      if (!node || (typeof node !== 'object' && typeof node !== 'function')) return null;
      if (!nodes.has(node)) nodes.set(node, ++sequence);
      return nodes.get(node);
    };
  }
  store.actions = store.actions || {};
  store.receipts = store.receipts || {};
  const action = store.actions[token] = {token, selector, prepared: null, events: []};
  const describe = node => ({targetId: store.identify(node), tag: node?.tagName || null,
    id: node?.id || null, connected: !!node?.isConnected});
  const capture = event => {
    const intended = doc.querySelector(selector);
    const matches = !!intended && (event.target === intended || intended.contains(event.target));
    const record = {type: event.type, trusted: event.isTrusted === true, matches,
      x: event.clientX, y: event.clientY, at: event.timeStamp,
      target: describe(event.target), intended: describe(intended), active: describe(doc.activeElement)};
    action.events.push(record);
    if (event.type === 'click' && record.trusted && matches && intended.isConnected && !intended.disabled) {
      store.receipts[token] = {trusted: true, targetId: store.identify(intended), at: event.timeStamp};
    }
  };
  const types = ['pointerdown', 'pointerup', 'mousedown', 'mouseup', 'click', 'focusin'];
  types.forEach(type => doc.addEventListener(type, capture, true));
  return () => types.forEach(type => doc.removeEventListener(type, capture, true));
}

export async function dispatchNativeClick(send, point) {
  // Both commands enter the same ordered CDP connection before awaiting a
  // response. No network round trip separates this one press/release pair.
  const pressed = send('Input.dispatchMouseEvent', {type:'mousePressed',button:'left',buttons:1,clickCount:1,x:point.x,y:point.y});
  const released = send('Input.dispatchMouseEvent', {type:'mouseReleased',button:'left',buttons:0,clickCount:1,x:point.x,y:point.y});
  await Promise.all([pressed, released]);
}
