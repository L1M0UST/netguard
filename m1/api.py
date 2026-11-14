"""Single-process M3 adapter: persistent tasks, bounded queue, shared files."""
import argparse
import hmac
import json
import os
import re
import shutil
import sqlite3
import threading
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4
from m1.run import process_task, now
from m1.handoff import read_batch
from m1.shared_files import list_files, descriptor, resolve_file


class APIError(Exception):
    def __init__(self, status, code, message):
        self.status, self.code, self.message = status, code, message


class TaskService:
    def __init__(self, workspace, max_pending=20):
        self.workspace = Path(workspace).resolve()
        self.root = self.workspace/'m1/api'
        self.root.mkdir(parents=True,exist_ok=True)
        self.db = self.root/'tasks.sqlite3'
        self.max_pending = max_pending
        self.mutex = threading.Lock()
        self.stop = threading.Event()
        self.wake = threading.Event()
        self.lock_path = self.root/'service.lock'
        try: fd = os.open(self.lock_path,os.O_CREAT|os.O_EXCL|os.O_WRONLY)
        except FileExistsError: raise RuntimeError('Service lock exists; stop old service before removing a stale m1/api/service.lock')
        os.close(fd)
        try:
            with closing(sqlite3.connect(self.db)) as conn:
                conn.execute('CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, request_id TEXT UNIQUE, request TEXT, record TEXT)')
                # Never auto-repeat possibly billable work interrupted by a crash.
                for task_id, record in conn.execute('SELECT id,record FROM tasks').fetchall():
                    data = json.loads(record)
                    if data['state'] in ('QUEUED','RUNNING'):
                        data.update(state='FAILED',updated_at=now(),error={'code':'SERVICE_RESTARTED','message':'Service interrupted; submit a new request to retry'})
                        conn.execute('UPDATE tasks SET record=? WHERE id=?',(json.dumps(data),task_id))
                conn.commit()
        except Exception:
            self.lock_path.unlink(missing_ok=True)
            raise
        self.worker = threading.Thread(target=self._work,name='m1-task-worker',daemon=False)
        self.worker.start()

    def _save(self, data):
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute('UPDATE tasks SET record=? WHERE id=?',(json.dumps(data),data['task_id']))
            conn.commit()

    def get(self, task_id):
        with closing(sqlite3.connect(self.db)) as conn:
            row=conn.execute('SELECT record FROM tasks WHERE id=?',(task_id,)).fetchone()
        if row is None: raise APIError(404,'TASK_NOT_FOUND','Unknown task')
        return json.loads(row[0])

    def submit(self, body):
        if not isinstance(body,dict) or set(body)-{'request_id','file_id','options'}:
            raise APIError(400,'INVALID_REQUEST','Allowed fields: request_id, file_id, options')
        request_id, file_id = body.get('request_id'),body.get('file_id')
        if not isinstance(request_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}',request_id):
            raise APIError(400,'INVALID_REQUEST','request_id must contain 1-100 letters, digits, underscore or hyphen')
        if not isinstance(file_id,str) or not re.fullmatch('[a-f0-9]{64}',file_id):
            raise APIError(400,'INVALID_REQUEST','file_id must come from GET /v1/files')
        options=body.get('options',{})
        if not isinstance(options,dict) or set(options)-{'session_window_seconds','profile_sample_size'}:
            raise APIError(400,'INVALID_OPTIONS','Unsupported options')
        for key,value in options.items():
            low,high=(1,86400) if key=='session_window_seconds' else (100,500)
            if type(value) is not int or not low<=value<=high: raise APIError(400,'INVALID_OPTIONS',key+' is out of range')
        canonical=json.dumps({'file_id':file_id,'options':options},sort_keys=True)
        with self.mutex, closing(sqlite3.connect(self.db)) as conn:
            row=conn.execute('SELECT request,record FROM tasks WHERE request_id=?',(request_id,)).fetchone()
            if row:
                if row[0]!=canonical: raise APIError(409,'IDEMPOTENCY_CONFLICT','request_id already used with different input')
                return json.loads(row[1]),False
            pending=sum(json.loads(row[0])['state'] in ('QUEUED','RUNNING') for row in conn.execute('SELECT record FROM tasks'))
            if pending>=self.max_pending: raise APIError(429,'QUEUE_FULL','Retry later with the same request_id')
            selected=next((f for f in list_files(self.workspace) if f['file_id']==file_id),None)
            if not selected: raise APIError(409,'FILE_CHANGED_OR_MISSING','Refresh GET /v1/files and select again')
            task_id='api-'+uuid4().hex
            data={'task_id':task_id,'request_id':request_id,'state':'QUEUED','created_at':now(),'updated_at':now(),
                  'file':selected,'options':options,'result':None,'error':None}
            conn.execute('INSERT INTO tasks VALUES (?,?,?,?)',(task_id,request_id,canonical,json.dumps(data)))
            conn.commit()
        self.wake.set()
        return data,True

    def _execute(self,data):
        snapshot_dir = self.root/'inputs'/data['task_id']
        try:
            source=resolve_file(self.workspace,data['file']['name'])
            if descriptor(source)['file_id']!=data['file']['file_id']:
                raise APIError(409,'FILE_CHANGED_OR_MISSING','Selected file changed before execution')
            snapshot_dir.mkdir(parents=True,exist_ok=False)
            snapshot=snapshot_dir/source.name
            shutil.copyfile(source,snapshot)
            if descriptor(source)['file_id']!=data['file']['file_id'] or snapshot.stat().st_size!=data['file']['size_bytes']:
                raise APIError(409,'FILE_CHANGED_OR_MISSING','File changed while copying')
            ready=process_task(self.workspace,{'task_id':data['task_id'],'input_files':[snapshot.relative_to(self.workspace).as_posix()],'options':data['options']})
            batch=read_batch(ready)
            data.update(state='SUCCEEDED',result={'batch_id':batch['batch_id'],'run_id':batch['run_id'],
                'consumption_key':batch['consumption_key'],'directory':ready.relative_to(self.workspace).as_posix(),
                'artifacts':batch['artifact_metadata'],'metrics':batch['status']['metrics'],
                'l3_status':batch['status'].get('l3_status'),'quality':batch['status'].get('quality')})
        except Exception as exc:
            code=exc.code if isinstance(exc,APIError) else 'PROCESSING_FAILED'
            # Avoid exposing provider secrets or machine paths in HTTP errors.
            data.update(state='FAILED',error={'code':code,'message':exc.message if isinstance(exc,APIError) else 'M1 processing failed; inspect local failed status','exception_type':type(exc).__name__})
        finally:
            data['updated_at']=now()
            self._save(data)

    def _work(self):
        while not self.stop.is_set():
            data=None
            with self.mutex, closing(sqlite3.connect(self.db)) as conn:
                for (record,) in conn.execute('SELECT record FROM tasks ORDER BY rowid'):
                    candidate=json.loads(record)
                    if candidate['state']=='QUEUED':
                        data=candidate
                        data.update(state='RUNNING',updated_at=now())
                        conn.execute('UPDATE tasks SET record=? WHERE id=?',(json.dumps(data),data['task_id']))
                        conn.commit()
                        break
            if data: self._execute(data)
            else:
                self.wake.wait(0.5)
                self.wake.clear()

    def close(self):
        self.stop.set(); self.wake.set()
        self.worker.join()
        self.lock_path.unlink(missing_ok=True)


def make_handler(service, token=''):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass

        def reply(self,status,data,content_type='application/json; charset=utf-8'):
            raw=data if isinstance(data,bytes) else json.dumps(data,ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header('Content-Type',content_type)
            self.send_header('Content-Length',str(len(raw)))
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.end_headers();self.wfile.write(raw)

        def dispatch(self):
            route=urlsplit(self.path).path
            if self.command=='GET' and route=='/':
                return self.reply(200,Path(__file__).with_name('select_file.html').read_bytes(),'text/html; charset=utf-8')
            if token and not hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+token):
                raise APIError(401,'UNAUTHORIZED','Bearer token required')
            if self.command=='GET' and route=='/v1/health':
                return self.reply(200,{'api_version':'1.0','status':'ok','worker_alive':service.worker.is_alive()})
            if self.command=='GET' and route=='/v1/files':
                return self.reply(200,{'files':list_files(service.workspace)})
            if self.command=='POST' and route=='/v1/tasks':
                if self.headers.get_content_type()!='application/json': raise APIError(415,'CONTENT_TYPE','Use application/json')
                if self.headers.get('Transfer-Encoding'): raise APIError(400,'INVALID_REQUEST','Chunked requests not supported')
                try: size=int(self.headers.get('Content-Length','0'))
                except ValueError: raise APIError(400,'INVALID_REQUEST','Invalid Content-Length')
                if not 0<size<=16384: raise APIError(413,'BODY_SIZE','Body must be 1-16384 bytes')
                try: body=json.loads(self.rfile.read(size))
                except (ValueError,UnicodeDecodeError): raise APIError(400,'INVALID_JSON','Invalid JSON body')
                data,created=service.submit(body)
                return self.reply(202 if created else 200,data)
            match=re.fullmatch(r'/v1/tasks/(api-[a-f0-9]{32})(/result)?',route)
            if self.command=='GET' and match:
                data=service.get(match[1])
                if match[2]:
                    if data['state']!='SUCCEEDED': raise APIError(409,'RESULT_NOT_READY','Task has no published result')
                    return self.reply(200,data['result'])
                return self.reply(200,data)
            raise APIError(404,'NOT_FOUND','Unknown endpoint')

        def handle_request(self):
            self.connection.settimeout(15)
            try: self.dispatch()
            except APIError as exc: self.reply(exc.status,{'error':{'code':exc.code,'message':exc.message}})
            except (BrokenPipeError,ConnectionResetError,TimeoutError): pass
            except Exception: self.reply(500,{'error':{'code':'INTERNAL_ERROR','message':'Internal service error'}})

        do_GET=handle_request
        do_POST=handle_request
    return Handler


def main():
    parser=argparse.ArgumentParser(description='M1 shared-file task API for M3')
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--port',type=int,default=8765)
    parser.add_argument('--max-pending',type=int,default=20)
    args=parser.parse_args()
    token=os.environ.get('M1_API_TOKEN','')
    if args.host not in ('127.0.0.1','localhost') and not token: parser.error('Non-loopback binding requires M1_API_TOKEN')
    if args.max_pending<1: parser.error('max-pending must be positive')
    service=TaskService(args.workspace,args.max_pending)
    try:
        server=ThreadingHTTPServer((args.host,args.port),make_handler(service,token))
        print(f'M1 selection page: http://{args.host}:{args.port}/',flush=True)
        try: server.serve_forever()
        except KeyboardInterrupt: pass
        finally: server.server_close()
    finally: service.close()


if __name__=='__main__': main()
