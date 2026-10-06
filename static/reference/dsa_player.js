/* Independent offline reference player. No networking, tenant access, or shared FA state. */
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else {
    root.DSAPlayer = api;
    if (root.document) {
      var boot = function () { api.mountAll(root.document, root.DSAFlows, root); };
      if (root.document.readyState === 'loading') root.document.addEventListener('DOMContentLoaded', boot, { once: true });
      else boot();
    }
  }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';
  var SPEEDS = [0.5, 1, 2];
  function scenario(flow, id) { return flow.scenarios.find(function (s) { return s.id === id; }) || flow.scenarios[0]; }
  function lastIndex(flow, state) {
    var selected = scenario(flow, state.scenarioId);
    return Number.isInteger(selected.stopAt) ? selected.stopAt : flow.stages.length - 1;
  }
  function initial(flow, options) {
    return { cursor: -1, status: 'idle', mode: 'guided', speed: 1, reducedMotion: !!(options && options.reducedMotion), scenarioId: flow.scenarios[0].id, generation: 0, replay: 0, remainingMs: 2200 };
  }
  function at(flow, state, index, status) {
    var next = Object.assign({}, state, { cursor: Math.max(0, Math.min(index, lastIndex(flow, state))), status: status, remainingMs: 2200 });
    if (next.cursor === lastIndex(flow, next)) next.status = Number.isInteger(scenario(flow, next.scenarioId).stopAt) ? 'stopped' : 'complete';
    return next;
  }
  // Pure state machine: injected timer tokens make stale callbacks harmless.
  function reduce(flow, state, action) {
    var next = state, type = action && action.type;
    var elapsed = Math.max(0, Number(action && action.elapsedMs) || 0);
    var remaining = Math.max(0, state.remainingMs - elapsed * state.speed);
    switch (type) {
      case 'PLAY': next = at(flow, Object.assign({}, state, { mode: 'auto' }), 0, 'playing'); break;
      case 'GUIDED': next = at(flow, Object.assign({}, state, { mode: 'guided' }), 0, 'guided'); break;
      case 'NEXT':
        if (state.status !== 'complete' && state.status !== 'stopped') next = at(flow, Object.assign({}, state, { mode: 'guided' }), state.cursor + 1, 'guided');
        break;
      case 'TICK':
        if (state.status === 'playing' && action.generation === state.generation) next = at(flow, state, state.cursor + 1, 'playing');
        break;
      case 'PAUSE': if (state.status === 'playing') next = Object.assign({}, state, { status: 'paused', remainingMs: remaining }); break;
      case 'RESUME':
        if (state.status === 'paused' || state.status === 'guided') next = Object.assign({}, state, { status: 'playing', mode: 'auto' });
        break;
      case 'BACK':
        if (state.cursor > 0) next = Object.assign({}, state, { cursor: state.cursor - 1, status: state.mode === 'auto' ? 'paused' : 'guided', remainingMs: 2200 });
        break;
      case 'REPLAY': if (state.cursor >= 0) next = Object.assign({}, state, { replay: state.replay + 1, remainingMs: 2200 }); break;
      case 'RESTART': next = Object.assign({}, initial(flow, state), { speed: state.speed, scenarioId: state.scenarioId, mode: state.mode }); break;
      case 'SPEED': if (SPEEDS.indexOf(Number(action.value)) !== -1) next = Object.assign({}, state, { speed: Number(action.value), remainingMs: state.status === 'playing' ? remaining : state.remainingMs }); break;
      case 'MOTION': next = Object.assign({}, state, { reducedMotion: !!action.value, status: state.status === 'playing' ? 'paused' : state.status, remainingMs: state.status === 'playing' ? remaining : state.remainingMs }); break;
      case 'SCENARIO':
        if (flow.scenarios.some(function (s) { return s.id === action.value; })) next = Object.assign({}, initial(flow, state), { speed: state.speed, scenarioId: action.value });
        break;
      default: break;
    }
    if (next === state) return state;
    return Object.assign({}, next, { generation: state.generation + 1 });
  }
  function stageStates(flow, state) {
    var stop = scenario(flow, state.scenarioId).stopAt;
    return flow.stages.map(function (_, i) {
      if (Number.isInteger(stop) && state.cursor >= stop && i > stop) return 'not_reached';
      if (i < state.cursor || (i === state.cursor && state.status === 'complete')) return 'completed';
      if (i === state.cursor) return state.status === 'stopped' ? 'stopped' : 'active';
      return 'pending';
    });
  }
  function controls(flow, state) {
    return { back: state.cursor > 0, next: state.status !== 'complete' && state.status !== 'stopped', replay: state.cursor >= 0, pause: state.status === 'playing', resume: state.status === 'paused' || state.status === 'guided', restart: state.cursor >= 0 };
  }
  function createController(flow, options) {
    options = options || {};
    var state = initial(flow, options), handle = null, dead = false;
    var now = options.now || function () { return Date.now(); };
    var startedAt = now(), lastNextAt = -Infinity;
    var schedule = options.schedule || function (fn, ms) { return setTimeout(fn, ms); };
    var cancel = options.cancel || function (id) { clearTimeout(id); };
    function clear() { if (handle !== null) { cancel(handle); handle = null; } }
    function dispatch(action) {
      if (dead) return state;
      var stamp = now();
      if (action.type === 'NEXT') {
        if (stamp - lastNextAt < (options.nextThrottleMs || 0)) return state;
        lastNextAt = stamp;
      } else if (action.type !== 'TICK') lastNextAt = -Infinity;
      var next = reduce(flow, state, Object.assign({}, action, { elapsedMs: state.status === 'playing' ? Math.max(0, stamp - startedAt) : 0 }));
      if (next === state) return state;
      clear(); state = next; startedAt = stamp;
      if (options.render) options.render(state);
      if (state.status === 'playing') {
        var token = state.generation;
        handle = schedule(function () { dispatch({ type: 'TICK', generation: token }); }, state.remainingMs / state.speed);
      }
      return state;
    }
    return { dispatch: dispatch, getState: function () { return state; }, destroy: function () { clear(); dead = true; }, isDestroyed: function () { return dead; } };
  }
  function keyboardAction(key, state, tag, editable) {
    if (editable || /^(INPUT|SELECT|TEXTAREA|BUTTON|A)$/.test(tag || '')) return null;
    if (key === 'ArrowRight') return { type: 'NEXT' };
    if (key === 'ArrowLeft') return { type: 'BACK' };
    if (key === 'Home') return { type: 'RESTART' };
    if (key === 'r' || key === 'R') return { type: 'REPLAY' };
    if (key === ' ' || key === 'Spacebar') return { type: state.status === 'playing' ? 'PAUSE' : state.status === 'paused' || state.status === 'guided' ? 'RESUME' : 'PLAY' };
    return null;
  }
  function mountAll(doc, registry, win) {
    if (!registry || !doc || !win) return [];
    var media = win.matchMedia ? win.matchMedia('(prefers-reduced-motion: reduce)') : null;
    var players = [], destroyed = false;
    function element(tag, text, className) {
      var node = doc.createElement(tag); if (text !== undefined) node.textContent = text; if (className) node.className = className; return node;
    }
    function stopOthers(selected) { players.forEach(function (p) { if (p !== selected) p.controller.dispatch({ type: 'PAUSE' }); }); }
    registry.flows.forEach(function (flow) {
      var host = doc.querySelector('[data-dsa-flow="' + flow.id + '"]');
      if (!host || host.querySelector('.dsa-player')) return;
      var shell = element('section', undefined, 'dsa-player');
      shell.tabIndex = 0; shell.setAttribute('aria-label', flow.title + ' reference player'); shell.dataset.flowId = flow.id;
      var title = element('h3', 'Explore: ' + flow.title); title.id = 'dsa-title-' + flow.id; shell.appendChild(title);
      shell.appendChild(element('p', 'REFERENCE SAMPLE · ' + registry.snapshot + ' · ' + flow.lane + ' · No tenant reads or actions', 'dsa-sample'));
      if (flow.note) shell.appendChild(element('p', flow.note, 'dsa-note'));
      var gates = element('ul', undefined, 'dsa-gates'); gates.setAttribute('aria-label', 'Web inspection prerequisites');
      ['URL Filtering', 'SSL/TLS Inspection', 'File Type Control'].forEach(function (name) {
        gates.appendChild(element('li', name + ': ' + (flow.web ? 'web prerequisite; reference only, not tenant-verified' : 'N/A in this walkthrough; apply only on the inline web branch')));
      }); shell.appendChild(gates);
      var toolbar = element('div', undefined, 'dsa-toolbar'), buttons = {};
      var actions = [['PLAY', 'Play All'], ['GUIDED', 'Guided Demo'], ['BACK', 'Back'], ['NEXT', 'Next'], ['REPLAY', 'Replay stage'], ['PAUSE', 'Pause'], ['RESUME', 'Resume'], ['RESTART', 'Restart']];
      actions.forEach(function (entry) {
        var b = element('button', entry[1]); b.type = 'button'; b.dataset.action = entry[0]; b.setAttribute('aria-label', entry[1] + ': ' + flow.title); toolbar.appendChild(b); buttons[entry[0]] = b;
      }); shell.appendChild(toolbar);
      var options = element('div', undefined, 'dsa-options');
      function select(label, id) { var l = element('label', label + ' '), input = element('select'); input.id = id; l.htmlFor = id; l.appendChild(input); options.appendChild(l); return input; }
      var speed = select('Speed', 'dsa-speed-' + flow.id);
      SPEEDS.forEach(function (n) { var option = element('option', n + '×'); option.value = String(n); speed.appendChild(option); }); speed.value = '1';
      var pick = select('Sample scenario', 'dsa-scenario-' + flow.id);
      flow.scenarios.forEach(function (s) { var option = element('option', s.label); option.value = s.id; pick.appendChild(option); });
      var motionLabel = element('label', undefined, 'dsa-motion'), motion = element('input'); motion.type = 'checkbox'; motion.checked = !!(media && media.matches); motionLabel.appendChild(motion); motionLabel.appendChild(doc.createTextNode(' Reduce motion')); options.appendChild(motionLabel); shell.appendChild(options);
      var scenarioNote = element('p', flow.scenarios[0].note, 'dsa-note'); shell.appendChild(scenarioNote);
      var status = element('p', 'Ready. Choose Play All or Guided Demo.', 'dsa-status'); status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite'); status.setAttribute('aria-atomic', 'true'); shell.appendChild(status);
      var timeline = element('ol', undefined, 'dsa-timeline'), stageNodes = [];
      flow.stages.forEach(function (s, index) {
        var li = element('li'); li.dataset.stageId = s.id; li.dataset.state = 'pending';
        var connector = element('span', undefined, 'dsa-connector'); connector.setAttribute('aria-hidden', 'true');
        var packet = element('span', '', 'dsa-packet'); connector.appendChild(packet);
        if (index > 0) li.appendChild(connector);
        var number = element('span', String(index + 1), 'dsa-stage-number'); li.appendChild(number);
        li.appendChild(element('strong', s.label)); var mark = element('span', 'Pending', 'dsa-stage-state'); li.appendChild(mark);
        var progress = element('span', '', 'dsa-progress-bar'); progress.setAttribute('aria-hidden', 'true'); li.appendChild(progress);
        timeline.appendChild(li); stageNodes.push({ li: li, mark: mark, connector: connector, packet: packet, progress: progress, number: number });
      }); shell.appendChild(timeline);
      var detail = element('div', undefined, 'dsa-stage-detail'), detailTitle = element('h4', 'Your selected stage will appear here'), detailText = element('p', 'Each step explains this flow using the saved reference snapshot.'); detail.appendChild(detailTitle); detail.appendChild(detailText); shell.appendChild(detail);
      shell.appendChild(element('p', 'Keyboard when the player panel is focused: → Next, ← Back, Space Play/Pause/Resume, Home Restart, R Replay. Play All runs this flow only. Starting another player pauses this one.', 'dsa-help'));
      if (flow.kind === 'figure') host.insertBefore(shell, host.querySelector('figcaption'));
      else host.insertBefore(shell, host.querySelector('ol'));
      var entry = { host: host, shell: shell, controller: null };
      var lastCursor = -1, lastReplay = -1;
      function render(state) {
        var states = stageStates(flow, state), enabled = controls(flow, state), selected = scenario(flow, state.scenarioId);
        shell.dataset.replaying = String(lastReplay >= 0 && lastReplay !== state.replay);
        shell.dataset.status = state.status; shell.dataset.reducedMotion = String(state.reducedMotion);
        shell.style.setProperty('--dsa-duration', (state.remainingMs / state.speed) + 'ms');
        shell.style.setProperty('--dsa-progress', String(1 - state.remainingMs / 2200));
        motion.checked = state.reducedMotion; speed.value = String(state.speed); pick.value = state.scenarioId;
        Object.keys(enabled).forEach(function (key) { buttons[key.toUpperCase()].disabled = !enabled[key]; });
        buttons.PLAY.disabled = state.status === 'playing';
        stageNodes.forEach(function (item, i) {
          item.li.dataset.state = states[i]; item.mark.textContent = states[i] === 'not_reached' ? 'Not reached in demo' : states[i].charAt(0).toUpperCase() + states[i].slice(1);
          if (i === state.cursor) item.li.setAttribute('aria-current', 'step'); else item.li.removeAttribute('aria-current');
          item.connector.dataset.state = states[i];
          if (i === state.cursor) {
            item.li.removeChild(item.progress); item.progress = element('span', '', 'dsa-progress-bar'); item.progress.setAttribute('aria-hidden', 'true'); item.li.appendChild(item.progress);
          }
          if (i === state.cursor && (lastCursor !== state.cursor || lastReplay !== state.replay)) {
            item.li.removeChild(item.number); item.number = element('span', String(i + 1), 'dsa-stage-number dsa-node-arrival'); item.li.insertBefore(item.number, item.li.querySelector('strong'));
            item.connector.removeChild(item.packet);
            item.packet = element('span', '', 'dsa-packet dsa-arrival'); item.connector.appendChild(item.packet);
          }
        });
        lastCursor = state.cursor; lastReplay = state.replay;
        if (state.cursor >= 0 && typeof timeline.scrollTo === 'function') {
          var activeNode = stageNodes[state.cursor].li;
          var left = activeNode.offsetLeft - timeline.offsetLeft;
          if (left < timeline.scrollLeft || left + activeNode.offsetWidth > timeline.scrollLeft + timeline.clientWidth) timeline.scrollTo({ left: Math.max(0, left - 20), behavior: state.reducedMotion ? 'auto' : 'smooth' });
        }
        scenarioNote.textContent = selected.note;
        if (state.cursor < 0) {
          status.textContent = 'Ready. Choose Play All or Guided Demo.';
          detailTitle.textContent = 'Your selected stage will appear here'; detailText.textContent = 'Each step explains this flow using the saved reference snapshot.';
        } else {
          var current = flow.stages[state.cursor], end = state.status === 'stopped' ? 'Sample stopped here. Later walkthrough stages are not reached; this is not observed traffic.' : state.status === 'complete' ? 'Reference walkthrough complete.' : state.status === 'guided' ? 'Guided demo. Choose Next to continue.' : state.status === 'paused' ? 'Paused.' : 'Playing automatically.';
          status.textContent = 'Stage ' + (state.cursor + 1) + ' of ' + flow.stages.length + ': ' + current.label + '. ' + end + (state.replay ? ' Replay ' + state.replay + '.' : '');
          detailTitle.textContent = current.label;
          detailText.textContent = current.detail + (state.status === 'stopped' ? ' Sample outcome: ' + selected.note : '');
        }
      }
      var controller = createController(flow, { reducedMotion: !!(media && media.matches), render: render, schedule: win.setTimeout.bind(win), cancel: win.clearTimeout.bind(win), now: win.performance && win.performance.now ? win.performance.now.bind(win.performance) : function () { return Date.now(); }, nextThrottleMs: 250 }); entry.controller = controller;
      actions.forEach(function (action) { buttons[action[0]].addEventListener('click', function () {
        if (['PLAY', 'GUIDED', 'RESUME', 'NEXT'].indexOf(action[0]) !== -1) stopOthers(entry);
        controller.dispatch({ type: action[0] });
      }); });
      speed.addEventListener('change', function () { controller.dispatch({ type: 'SPEED', value: speed.value }); });
      pick.addEventListener('change', function () { controller.dispatch({ type: 'SCENARIO', value: pick.value }); });
      motion.addEventListener('change', function () { controller.dispatch({ type: 'MOTION', value: motion.checked }); });
      shell.addEventListener('keydown', function (event) {
        if (event.repeat) return;
        var action = keyboardAction(event.key, controller.getState(), event.target.tagName, event.target.isContentEditable);
        if (!action) return; event.preventDefault();
        if (['PLAY', 'RESUME', 'NEXT'].indexOf(action.type) !== -1) stopOthers(entry);
        controller.dispatch(action);
      });
      if (flow.kind !== 'figure') host.addEventListener('toggle', function () { if (!host.open) controller.dispatch({ type: 'PAUSE' }); });
      var zoom = host.querySelector('.zoom');
      if (zoom) zoom.addEventListener('click', function () { controller.dispatch({ type: 'PAUSE' }); });
      render(controller.getState()); players.push(entry);
    });
    if (!players.length) return players;
    function pauseAll() { players.forEach(function (p) { p.controller.dispatch({ type: 'PAUSE' }); }); }
    function visibility() { if (doc.hidden) pauseAll(); }
    function motionChange(e) { players.forEach(function (p) { p.controller.dispatch({ type: 'MOTION', value: e.matches }); }); }
    function destroyAll() {
      if (destroyed) return; destroyed = true;
      players.forEach(function (p) { p.controller.destroy(); });
      doc.removeEventListener('visibilitychange', visibility); win.removeEventListener('pagehide', pauseAll);
      if (media && media.removeEventListener) media.removeEventListener('change', motionChange);
    }
    doc.addEventListener('visibilitychange', visibility); win.addEventListener('pagehide', pauseAll);
    if (media && media.addEventListener) media.addEventListener('change', motionChange);
    players.destroy = destroyAll;
    return players;
  }
  return { initial: initial, reduce: reduce, stageStates: stageStates, controls: controls, createController: createController, keyboardAction: keyboardAction, mountAll: mountAll, lastIndex: lastIndex };
}));
