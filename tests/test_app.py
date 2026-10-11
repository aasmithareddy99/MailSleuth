import os, tempfile
os.environ['MAILSLEUTH_DB'] = os.path.join(tempfile.gettempdir(), 'mailsleuth_test_suite.sqlite3')
try: os.remove(os.environ['MAILSLEUTH_DB'])
except FileNotFoundError: pass
from fastapi.testclient import TestClient
import main

client = TestClient(main.app)

def test_health_and_dashboard():
    assert client.get('/health').json()['status'] == 'ok'
    assert client.get('/').status_code == 200

def test_analysis_exposes_relay_and_auth():
    payload = {'sender':'Security <security@paypa1.example>','subject':'URGENT verify your account',
      'body':'Confirm your password at http://192.0.2.4/login',
      'raw_headers':'From: Security <security@paypa1.example>\r\nReply-To: help@other.example\r\nReceived: from host (203.0.113.10) by mx.example\r\nAuthentication-Results: mx.example; spf=fail; dkim=pass; dmarc=fail',
      'include_ml':False,'include_threat_intel':False}
    r=client.post('/api/analyze',json=payload)
    assert r.status_code == 200, r.text
    data=r.json()
    assert data['risk_score'] > 0
    assert data['relay_analysis']['hop_count'] == 1
    assert data['relay_analysis']['hops'][0]['ips'] == ['203.0.113.10']
    assert data['auth_results']['SPF'] == 'fail'
    assert data['id']

def test_history_summary_export_report():
    payload={'sender':'test@example.org','subject':'hello','body':'Ordinary meeting notes','include_ml':False,'include_threat_intel':False}
    r=client.post('/api/analyze',json=payload)
    assert r.status_code==200
    analysis_id=r.json()['id']
    assert client.get('/api/history?q=test').status_code==200
    assert client.get('/api/dashboard-summary').json()['total_analyses'] >= 1
    report=client.get(f'/api/report/{analysis_id}')
    assert report.status_code==200 and 'Forensic Report' in report.text
    assert client.get('/api/export.csv').status_code==200

def test_invalid_upload_extension():
    r=client.post('/api/analyze-file',files={'file':('not.txt',b'hello','text/plain')})
    assert r.status_code==400

def test_payload_validation():
    r=client.post('/api/analyze',json={'sender':'x','subject':'x','body':'x'*200001})
    assert r.status_code==422


def test_eml_upload_and_report_escaping():
    raw = b"From: Security <security@paypa1.example>\r\nSubject: URGENT verify account\r\nReceived: from host (203.0.113.5) by mx.example\r\nAuthentication-Results: mx.example; spf=fail\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nVerify your account and password at http://192.0.2.2/login"
    r=client.post('/api/analyze-file',files={'file':('sample.eml',raw,'message/rfc822')})
    assert r.status_code==200, r.text
    data=r.json()
    assert data['relay_analysis']['hop_count']==1
    assert data['rule_score'] > 0

def test_threat_intel_disabled_by_default():
    r=client.post('/api/analyze',json={'sender':'person@example.org','subject':'hello','body':'notes','include_threat_intel':False,'include_ml':False})
    assert r.status_code==200
    assert r.json()['threat_intelligence']['enabled'] is False


def test_dashboard_contains_relay_integration():
    page=client.get('/').text
    assert 'id="relay"' in page
    assert 'd.relay_analysis' in page
    assert '/api/report/' in page

def test_ml_status_endpoint():
    data=client.get('/api/ml/status').json()
    assert 'sklearn_installed' in data
    assert 'dataset_note' in data
