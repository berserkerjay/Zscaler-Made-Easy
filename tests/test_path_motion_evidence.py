"""Configuration and inventory must not animate as observed delivery."""
import json
import pathlib
import subprocess
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def model(value):
    script = "const fs=require('fs'),vm=require('vm'),c={window:{}};vm.createContext(c);vm.runInContext(fs.readFileSync('static/path_motion.js','utf8'),c);process.stdout.write(JSON.stringify(c.pmModel(JSON.parse(fs.readFileSync(0,'utf8')))));"
    p = subprocess.run(['node', '-e', script], cwd=ROOT, input=json.dumps(value), text=True, capture_output=True, check=True)
    return json.loads(p.stdout)


@pytest.mark.parametrize('outcome', ['enforce', 'monitor', 'blocked', 'bypassed', 'blind', 'unknown', 'out_of_scope', 'none'])
def test_configuration_outcomes_never_animate_a_transaction(outcome):
    m = model({'trace': {'evidence_mode': 'configuration', 'outcome': outcome, 'hops': [{'key': 'dlp', 'status': outcome, 'label': 'Web DLP'}]}})
    assert m['mode'] == 'configuration' and not m['routes'] and not m['stops']
    assert 'no transaction' in m['summary'][0]


@pytest.mark.parametrize('channel', ['endpoint', 'email', 'saas'])
def test_channel_inventory_is_not_a_broken_detection_chain(channel):
    m = model({'trace': {'evidence_mode': 'configuration', 'channels': {channel: {'status': 'inventory', 'detail': 'Two enabled rules'}}}})
    assert any('inventory read; this channel was not tested' in x for x in m['summary'])
    assert not m['routes'] and not m['stops']


@pytest.mark.parametrize('field', ['incident_receiver', 'icap_server'])
def test_receiver_flag_alone_cannot_reach_workflow_automation(field):
    rule = {'name': 'Candidate', 'engines': ['Engine'], field: True}
    m = model({'trace': {'outcome': 'enforce', 'hops': [{'key': 'dlp', 'rules': [rule]}]}})
    routes = [r for r in m['routes'] if 'waint>wa' in r['edges']]
    assert routes and all(r['stop'] is not None and r['tone'] == 'unread' for r in routes)


def test_observed_incident_does_not_prove_siem_delivery_or_event_action():
    m = model({'live': [{'channel': 'web', 'rules': ['Rule'], 'enforcement': 'monitor'}]})
    assert not any('nss>siem' in r['edges'] for r in m['routes'])
    text = ' '.join(m['summary'])
    assert 'currently configured monitoring' in text and 'whether data left are not established' in text
