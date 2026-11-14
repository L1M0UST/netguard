"""Isolated acceptance suite; never writes demo results into the user's workspace."""
import hashlib
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from demo_bundle import produce
from workspace_io import Workspace, Bundle, atomic_json
from m3_services import answer_question, validate_upload, redact_value
from retention import expire_uploads


class Acceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.root=Path(cls.temp.name)
        cls.data=cls.root/'data'; cls.ws=cls.root/'shared'
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); cls.port=sock.getsockname()[1]
        cls.env={**os.environ,'NETGUARD_DATA_DIR':str(cls.data),'NETGUARD_WORKSPACE':str(cls.ws),
                 'NETGUARD_LLM_ENABLED':'0','NO_PROXY':'127.0.0.1,localhost','no_proxy':'127.0.0.1,localhost'}
        cls.start_server()

    @classmethod
    def start_server(cls):
        cls.process=subprocess.Popen([sys.executable,'-m','uvicorn','server:app','--host','127.0.0.1','--port',str(cls.port)],env=cls.env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                with urlopen(f'http://127.0.0.1:{cls.port}/health',timeout=1): return
            except OSError: time.sleep(.1)
        raise RuntimeError('isolated server failed to start')

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate();cls.process.wait(timeout=10)
        # Windows 上子进程句柄释放略有延迟，立即清理临时目录会撞 WinError 32。
        try:
            cls.temp.cleanup()
        except (PermissionError, OSError):
            time.sleep(1.5)
            shutil.rmtree(cls.temp.name, ignore_errors=True)

    def request(self,path,body=None,raw=None,content_type=None):
        data=json.dumps(body).encode() if body is not None else raw
        req=Request(f'http://127.0.0.1:{self.port}'+path,data=data,headers={'Content-Type':content_type or 'application/json'})
        try:
            with urlopen(req,timeout=10) as r:return r.status,r.read()
        except HTTPError as e:return e.code,e.read()

    def task(self):
        raw=b'--test-boundary\r\nContent-Disposition: form-data; name="file"; filename="test.csv"\r\nContent-Type: text/csv\r\n\r\ntimestamp,src_ip\n2026-09-17,192.0.2.1\n\r\n--test-boundary--\r\n'
        status,result=self.request('/api/v1/files',raw=raw,content_type='multipart/form-data; boundary=test-boundary')
        self.assertEqual(status,200,result)
        status,result=self.request('/api/v1/tasks',{'file_ids':[json.loads(result)['file_id']]})
        self.assertEqual(status,200,result)
        return json.loads(result)['task_id']

    def test_lifecycle_and_restart(self):
        task=self.task()
        self.assertEqual(json.loads(self.request('/api/v1/tasks/'+task)[1])['status'],'queued')
        self.assertEqual(self.request('/api/v1/reports/'+task)[0],409)
        self.assertEqual(self.request('/api/v1/chat',{'task_id':task,'message':'总结'})[0],409)
        produce(self.ws,task)
        status,result=self.request('/api/v1/tasks/'+task)
        value=json.loads(result);self.assertEqual(value['status'],'completed')
        self.assertTrue(value['degraded'])
        aid=value['alerts'][0]['alert_id']
        self.assertEqual(self.request(f'/api/v1/tasks/{task}/view-alert/{aid}',{})[0],200)
        self.assertIn({'task_id':task,'alert_id':aid},json.loads(self.request('/api/v1/read-alerts')[1]))
        status,chat=self.request('/api/v1/chat',{'task_id':task,'message':'总结并解释证据'})
        self.assertEqual(status,200); self.assertIn(b'event: done',chat)
        self.assertIn(('event-'+task).encode(),chat)
        self.assertEqual(len(json.loads(self.request(f'/api/v1/tasks/{task}/chat-history')[1])),1)
        self.assertEqual(self.request('/api/v1/reports/'+task+'?format=pdf')[1][:5],b'%PDF-')
        status, exported = self.request('/api/v1/reports/'+task+'?format=json')
        self.assertEqual(status,200)
        package=json.loads(exported)
        self.assertEqual(package['export_version'],'NetGuardEvidencePackage.v1')
        self.assertEqual(package['scope'],'task')
        self.assertNotIn('bundle',package)
        self.assertEqual(len(package['attack_chains']),len(value['chains']))
        chain_id=value['chains'][0]['chain_id']
        chain_package=json.loads(self.request('/api/v1/reports/'+task+'?format=json&chain_id='+chain_id)[1])
        self.assertEqual(chain_package['scope'],'attack_chain')
        self.assertEqual([chain_id],[chain['chain_id'] for chain in chain_package['attack_chains']])
        type(self).process.terminate();type(self).process.wait(timeout=10);type(self).start_server()
        self.assertEqual(json.loads(self.request('/api/v1/tasks/'+task)[1])['status'],'completed')
        self.assertIn({'task_id':task,'alert_id':aid},json.loads(self.request('/api/v1/read-alerts')[1]))
        self.assertGreaterEqual(len(json.loads(self.request(f'/api/v1/tasks/{task}/audit')[1])),4)
        (self.ws/'m2/READY'/task/'bundle.json').write_bytes(b'{}')
        failed=json.loads(self.request('/api/v1/tasks/'+task)[1])
        self.assertEqual(failed['status'],'failed');self.assertEqual(failed['alerts'],[])
        self.assertEqual(self.request('/api/v1/reports/'+task)[0],409)

    def test_validation_and_retrieval(self):
        root=self.root/'validation';produce(root,'valid')
        bundle=Workspace(root).read_bundle('valid')
        answer,citations,degraded=answer_question(bundle,'xyz-nonexistent-49999',knowledge_dir=Path('knowledge'))
        self.assertIn('没有找到匹配',answer);self.assertEqual(citations,[]);self.assertTrue(degraded)
        answer,citations,_=answer_question(bundle,'解释证据',knowledge_dir=Path('knowledge'))
        self.assertTrue(any(c['source_type']=='knowledge' for c in citations))
        bundle['chains'][0]['optional_note']='preserved'
        self.assertEqual(Bundle.model_validate(bundle).model_dump()['chains'][0]['optional_note'],'preserved')
        bundle['versions'].pop('model_version')
        with self.assertRaises(ValueError):Bundle.model_validate(bundle)
        fake=self.root/'fake';fake.write_bytes(b'MZ-not-csv')
        with self.assertRaises(ValueError):validate_upload(fake,'wrong.csv')
        with self.assertRaises(ValueError):validate_upload(fake,'wrong.xlsx')
        with self.assertRaises(ValueError):validate_upload(fake,'wrong.pcap')
        self.assertNotIn('secret',str(redact_value({'token':'secret','summary':'password=secret a@example.com'})))

    def test_retention_waiting_and_completed(self):
        root=self.root/'retention';root.mkdir();ws=Workspace(root/'shared')
        file_id='a'*32;(root/file_id).write_bytes(b'copy')
        records={file_id:{'uploaded_at_epoch':1}}
        tasks={'retained':{'task_id':'retained','status':'queued','file_ids':[file_id]}}
        self.assertEqual(expire_uploads(records,tasks,root,ws,1,10000),[])
        tasks['retained']['status']='completed'
        self.assertEqual(expire_uploads(records,tasks,root,ws,1,10000),[file_id])
        self.assertFalse((root/file_id).exists())

if __name__=='__main__':unittest.main()
