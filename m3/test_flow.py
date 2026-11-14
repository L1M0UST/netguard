"""Run against the local BFF: python test_flow.py."""
import json
import urllib.request
import urllib.error

BASE = 'http://127.0.0.1:8001'
def request(path, data=None, content_type='application/json'):
    req = urllib.request.Request(BASE + path, data=data, headers={'Content-Type':content_type})
    return urllib.request.urlopen(req, timeout=15)

payload = b'--demo\r\nContent-Disposition: form-data; name="file"; filename="test.csv"\r\nContent-Type: text/csv\r\n\r\ntime,source\n1,192.0.2.10\r\n--demo--\r\n'
uploaded = json.load(request('/api/v1/files',payload,'multipart/form-data; boundary=demo'))
task = json.load(request('/api/v1/tasks',json.dumps({'file_ids':[uploaded['file_id']]}).encode()))
task_id = task['task_id']
try:
    request('/api/v1/reports/'+task_id)
    raise AssertionError('Premature export should fail')
except urllib.error.HTTPError as error:
    assert error.code == 409
from demo_bundle import produce
produce('shared_workspace', task_id)
events = request('/api/v1/tasks/'+task_id+'/stream').read().decode()
assert '"progress": 100' in events and 'completed' in events
alerts = json.load(request('/api/v1/tasks/'+task_id+'/alerts'))
assert alerts and alerts[0]['alert_id']
task = json.load(request('/api/v1/tasks/'+task_id))
chain = json.load(request('/api/v1/attack-chains/'+task['chain']['chain_id']))
assert chain['evidence_ids'] == alerts[0]['event_ids']
assert chain['evidence_event_ids'] == alerts[0]['event_ids']
chat = request('/api/v1/chat',json.dumps({'task_id':task_id,'chain_id':chain['chain_id'],'message':'解释证据'}).encode()).read().decode()
assert all('event: '+name in chat for name in ['delta','evidence','done'])
assert json.load(request('/api/v1/reports/'+task_id+'?format=json'))['task_id'] == task_id
assert request('/api/v1/reports/'+task_id+'?format=pdf').read().startswith(b'%PDF')
print('PASS: upload -> task -> SSE -> alerts/chain -> streamed chat/evidence -> JSON/PDF; premature export rejected')
