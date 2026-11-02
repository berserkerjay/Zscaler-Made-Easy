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
      // The same node with the same box (centre and, when measured, size)
      // over consecutive samples: a control that is still growing, shrinking
      // or moving is not clicked yet.
      if (previous && last.targetId === previous.targetId && Math.abs(last.x - previous.x) <= .5 && Math.abs(last.y - previous.y) <= .5
        && Math.abs((last.w ?? 0) - (previous.w ?? 0)) <= .5 && Math.abs((last.h ?? 0) - (previous.h ?? 0)) <= .5) return last;
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
  // `interactive` says whether a stray click could have activated another
  // control (null when unknown, which is treated as interactive).
  const controls = 'a[href],button,input,select,textarea,summary,label,[onclick],[role="button"],[role="link"],[role="checkbox"],[role="radio"],[role="tab"],[contenteditable="true"]';
  const describe = node => ({targetId: store.identify(node), tag: node?.tagName || null,
    id: node?.id || null, connected: !!node?.isConnected,
    interactive: typeof node?.closest === 'function' ? !!node.closest(controls) : null});
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

// Why a dispatched native click produced no receipt, from the probe's events
// for that one attempt. Only a miss that provably left every control's
// handlers untouched may be pressed again: nothing reached the page, a press
// whose click was cancelled (the pressed node was removed or replaced before
// the release, as a re-render does), or a click that landed on an inert
// element (the control moved). A click that reached the intended control, or
// any other control, is never repeated.
export function classifyMissedClick(events, preparedTargetId) {
  const trusted = (events || []).filter(e => e && e.trusted);
  const clicks = trusted.filter(e => e.type === 'click');
  if (clicks.some(e => e.matches || (preparedTargetId != null && e.target?.targetId === preparedTargetId)))
    return {reason: 'click-reached-target-without-receipt', retryable: false};
  const stray = clicks.find(e => e.target?.interactive !== false);
  if (stray) return {reason: 'click-landed-on-another-control', retryable: false, target: stray.target};
  if (clicks.length) return {reason: 'click-landed-on-inert-element', retryable: true, target: clicks[0].target};
  if (trusted.some(e => e.type === 'pointerdown' || e.type === 'mousedown')) return {reason: 'press-without-click', retryable: true};
  return {reason: 'no-input-reached-page', retryable: true};
}

// One native click that the page must receive. Each attempt re-measures the
// target until it is stable, enabled and hit-testable, hovers, re-measures,
// then dispatches one press/release pair and waits the same bounded window
// for the trusted receipt. A miss is retried only when classifyMissedClick
// allows it, at most `attempts` times in all; the final error names every
// attempt's reason and events.
export async function clickUntilReceived({label, stablePoint, hover, dispatch, awaitReceipt, evidence, attempts = 3, onAttempt = () => {}}) {
  const missed = [];
  let seen = 0;
  const report = () => JSON.stringify(missed);
  for (let attempt = 1; attempt <= attempts; attempt++) {
    let point;
    try {
      point = await stablePoint();
      await hover(point);
      point = await stablePoint();
    } catch (error) {
      if (missed.length) error.message += `; earlier missed native clicks on ${label}: ${report()}`;
      throw error;
    }
    onAttempt({attempt, point});
    await dispatch(point);
    if (await awaitReceipt()) return {point, attempt, missed};
    const state = await evidence() || {};
    if (state.received) return {point, attempt, missed};
    const events = state.events || [], fresh = events.slice(seen);
    seen = events.length;
    const verdict = classifyMissedClick(fresh, point.targetId);
    missed.push({attempt, x: point.x, y: point.y, targetId: point.targetId ?? null, reason: verdict.reason, retryable: verdict.retryable,
      events: fresh.map(e => `${e.type}${e.trusted ? '' : '(untrusted)'}>${e.target?.tag || '?'}${e.target?.id ? '#' + e.target.id : ''}${e.matches ? '(target)' : ''}`)});
    if (!verdict.retryable) break;
  }
  throw new Error(`Native click on ${label} was not received after ${missed.length} of ${attempts} attempt(s): ${report()}`);
}
