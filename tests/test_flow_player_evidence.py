"""Production SVG player behavior under an offline deterministic DOM, not browser QA."""
import json
import pathlib
import subprocess
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(body):
    pre = "const H=require('./tests/path_motion_dom.js');const w=H.load('./static/flow_anim.js',{reduce:true});const FA=w.ctx.FA,host=w.container();const model={dest:'example.test',stop:-1,hops:[{key:'channel',label:'Channel',tone:'warn',status:'configured'},{key:'url',label:'URL Filtering',tone:'warn',status:'unverified'},{key:'ssl',label:'SSL Inspection',tone:'idle',status:'not_applicable'}]};"
    script = pre + "(async()=>{" + body + "})().catch(e=>{console.error(e);process.exit(1)});"
    result = subprocess.run(['node', '-e', script], cwd=ROOT, text=True, capture_output=True, check=True)
    return json.loads(result.stdout)


def test_first_unverified_stage_is_not_coloured_as_passed():
    r = run("FA.hopPlayer(host,model);process.stdout.write(JSON.stringify(host.querySelectorAll('.fa-box')[0].getAttribute('class')));")
    assert 'warn' in r and 'pass' not in r


def test_play_all_cannot_pass_a_stop_at_the_first_stage():
    r = run("model.stop=0;let hops=0,done=0;const p=FA.hopPlayer(host,model,{onHop(){hops++},onDone(){done++}});p.play();process.stdout.write(JSON.stringify({hops,done}));")
    assert r == {'hops': 0, 'done': 1}


def test_guided_next_advances_exactly_one_stage():
    r = run("let hops=0;const p=FA.hopPlayer(host,model,{onHop(){hops++}});p.step();await Promise.resolve();await Promise.resolve();process.stdout.write(JSON.stringify(hops));")
    assert r == 1


def test_rapid_guided_next_is_inflight_guarded():
    r = run("let hops=0;const p=FA.hopPlayer(host,model,{onHop(){hops++}});p.step();p.step();await Promise.resolve();await Promise.resolve();process.stdout.write(JSON.stringify(hops));")
    assert r == 1


def test_guided_next_after_completion_does_not_restart():
    r = run("let hops=0;const p=FA.hopPlayer(host,model,{onHop(){hops++}});p.play();p.step();await Promise.resolve();process.stdout.write(JSON.stringify(hops));")
    assert r == 2


def test_unknown_live_action_uses_unknown_lane_not_monitor():
    r = run("const p=FA.live(host);await p.push(FA.liveModel({channel:'other',enforcement:'unknown'}));process.stdout.write(JSON.stringify(p.counts()));")
    assert r['unknown_action'] == 1 and r['monitor'] == 0 and r['unknown'] == 1


@pytest.mark.parametrize('channel,expected', [('web', 'unverified'), ('endpoint', 'not applicable'), ('email', 'not applicable'), ('saas', 'not applicable'), ('other', 'unverified')])
def test_live_controls_are_rendered_with_honest_applicability(channel, expected):
    r = run("const p=FA.live(host);await p.push(FA.liveModel({channel:" + json.dumps(channel) + ",enforcement:'unknown'}));process.stdout.write(JSON.stringify(host.querySelectorAll('.fa-box').slice(-3).map(x=>x.textContent)));")
    assert len(r) == 3
    assert all(expected in text for text in r)
    assert all(any(name in text for text in r) for name in ['URL Filtering', 'SSL Inspection', 'File Type Control'])


def test_restart_removes_inflight_packets_and_cancels_old_frames():
    r = run("w.mq.matches=false;const p=FA.hopPlayer(host,model);p.play();w.frames(3);const before=host.querySelectorAll('.fa-dot').length;p.reset();const after=host.querySelectorAll('.fa-dot').length;w.frames(10);process.stdout.write(JSON.stringify({before,after,later:host.querySelectorAll('.fa-dot').length,pending:w.pending()}));")
    assert r['before'] > 0 and r['after'] == 0 and r['later'] == 0 and r['pending'] == 0
