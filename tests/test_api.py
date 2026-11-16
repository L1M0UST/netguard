import json
import threading
import time
import unittest
import subprocess
import sys
import sqlite3
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from unittest.mock import patch
from tests.test_m1 import test_workspace
from m1.api import TaskService, make_handler, APIError
from m1.shared_files import list_files, resolve_file
from m1.run import process_task


@contextmanager
def setup_service():
    with test_workspace() as root:
        (root/'incoming').mkdir()
        (root/'m1').mkdir(exist_ok=True)
        (root/'m1/config.json').write_text(json.dumps({'output':{'format':'parquet'},'llm':{'enabled':False},'mapping_llm':{'enabled':False},'threatbook':{'enabled':False},'ml_detector':{'enabled':False}}))
        (root/'incoming/web.csv').write_text('Time,Source IP,Destination,URL,Payload\n2026-01-01T00:00:00Z,10.0.0.1,10.0.0.2,/test,id=1 or 1=1\n')
        service=TaskService(root)
        try: yield root,service
        finally: service.close()


def completed(service,task_id):
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        data=service.get(task_id)
        if data['state'] in ('SUCCEEDED','FAILED'): return data
        time.sleep(.02)
    raise AssertionError('task did not finish')


class APITest(unittest.TestCase):
    def test_cli_direct_file_without_manifest(self):
        with setup_service() as (root,service):
            result=subprocess.run([sys.executable,'-m','m1.run','--workspace',str(root),'--file','web.csv'],capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertFalse((root/'manifests').exists())
            self.assertEqual(len(list((root/'m1/ready').glob('*/*/READY.json'))),1)

    def test_restart_marks_interrupted_task_without_retry(self):
        with test_workspace() as root:
            service=TaskService(root)
            service.close()
            with sqlite3.connect(root/'m1/api/tasks.sqlite3') as conn:
                conn.execute('INSERT INTO tasks VALUES (?,?,?,?)',('api-'+'a'*32,'old','{}',json.dumps({'task_id':'api-'+'a'*32,'state':'RUNNING'})))
            conn.close()
            restarted=TaskService(root)
            try:
                record=restarted.get('api-'+'a'*32)
                self.assertEqual(record['state'],'FAILED')
                self.assertEqual(record['error']['code'],'SERVICE_RESTARTED')
            finally: restarted.close()

    def test_http_contract_and_no_manifest(self):
        with setup_service() as (root,service):
            server=ThreadingHTTPServer(('127.0.0.1',0),make_handler(service,'test-token'))
            thread=threading.Thread(target=server.serve_forever);thread.start()
            base='http://127.0.0.1:'+str(server.server_port)
            def request(path,body=None,token='test-token'):
                req=Request(base+path,data=json.dumps(body).encode() if body is not None else None,
                    headers={'Content-Type':'application/json','Authorization':'Bearer '+token})
                try:
                    with urlopen(req,timeout=10) as response: return response.status,json.load(response)
                except HTTPError as exc:
                    with exc: return exc.code,json.load(exc)
            try:
                self.assertEqual(request('/v1/files',token='wrong')[0],401)
                code,files=request('/v1/files');self.assertEqual(code,200)
                body={'request_id':'m3-001','file_id':files['files'][0]['file_id']}
                code,task=request('/v1/tasks',body);self.assertEqual(code,202)
                code,repeated=request('/v1/tasks',body)
                self.assertEqual((code,repeated['task_id']),(200,task['task_id']))
                self.assertEqual(request('/v1/tasks',{**body,'options':{'session_window_seconds':60}})[0],409)
                data=completed(service,task['task_id'])
                self.assertEqual(data['state'],'SUCCEEDED',data)
                code,result=request('/v1/tasks/'+task['task_id']+'/result')
                self.assertEqual(code,200)
                self.assertEqual(result['metrics']['input_records'],1)
                self.assertIn('suspicious_events',result['artifacts'])
                self.assertFalse((root/'manifests').exists())
                self.assertTrue((root/result['directory']/'READY.json').is_file())
            finally: server.shutdown();server.server_close();thread.join()

    def test_validation_and_file_boundaries(self):
        with setup_service() as (root,service):
            for name in ('../config.json','C:\\secret.csv','/etc/passwd','file.csv:secret'):
                with self.assertRaises(ValueError): resolve_file(root,name)
            f=list_files(root)[0]
            for body in ({'request_id':'a','file_id':'bad'}, {'request_id':'a','file_id':f['file_id'],'options':{'llm':True}},
                         {'request_id':'a','file_id':f['file_id'],'options':{'session_window_seconds':True}}):
                with self.assertRaises(APIError): service.submit(body)
            (root/'incoming/web.csv').write_text('changed')
            with self.assertRaises(APIError) as caught: service.submit({'request_id':'a','file_id':f['file_id']})
            self.assertEqual(caught.exception.code,'FILE_CHANGED_OR_MISSING')
            with self.assertRaises(RuntimeError): TaskService(root)

    def test_changed_queued_input_and_failure(self):
        with setup_service() as (root,service):
            entered,release=threading.Event(),threading.Event()
            real=process_task
            def blocked(*args):
                entered.set();self.assertTrue(release.wait(10));return real(*args)
            with patch('m1.api.process_task',side_effect=blocked):
                file_id=list_files(root)[0]['file_id']
                first,_=service.submit({'request_id':'first','file_id':file_id})
                try:
                    self.assertTrue(entered.wait(10))
                    second,_=service.submit({'request_id':'second','file_id':file_id})
                    service.max_pending=2
                    with self.assertRaises(APIError) as caught: service.submit({'request_id':'third','file_id':file_id})
                    self.assertEqual(caught.exception.code,'QUEUE_FULL')
                    (root/'incoming/web.csv').write_text('changed while queued')
                finally: release.set()
                self.assertEqual(completed(service,first['task_id'])['state'],'SUCCEEDED')
                failed=completed(service,second['task_id'])
                self.assertEqual(failed['error']['code'],'FILE_CHANGED_OR_MISSING')

    def test_processing_failure_is_persisted(self):
        with setup_service() as (root,service):
            with patch('m1.api.process_task',side_effect=RuntimeError('secret-provider-details')):
                task,_=service.submit({'request_id':'failure','file_id':list_files(root)[0]['file_id']})
                failed=completed(service,task['task_id'])
                self.assertEqual(failed['state'],'FAILED')
                self.assertNotIn('secret-provider-details',json.dumps(failed))
