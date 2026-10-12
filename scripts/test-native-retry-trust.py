#!/usr/bin/env python3
"""Root-only genuine fixed-case proof/import integration; disposable test DB only.
All secrets remain in private operator files. No provider or productive mutation.
"""
import argparse,hashlib,hmac,json,os,pathlib,secrets,shutil,subprocess,time,uuid
D=['docker','-H','unix:///var/run/docker.sock']
COMMIT='34416282cad05e6a31d0d9e6e3722e6721fd6def'
DOMAIN=b'clawforge-native-retry-after-verification-v1\0'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def command(cmd,**kw):
 r=subprocess.run(cmd,capture_output=True,text=True,**kw)
 if r.returncode:raise RuntimeError('reviewed isolated operation failed: '+pathlib.Path(cmd[0]).name)
 return r.stdout

def main():
 ap=argparse.ArgumentParser()
 for name in ['repair-repo','provenance','holdout','binary','runtime-image','pg-image','output-root']:ap.add_argument('--'+name,required=True)
 a=ap.parse_args();assert os.getuid()==0
 root=pathlib.Path(a.output_root);assert not root.exists();root.mkdir(mode=0o755)
 source=root/'source';source.mkdir(mode=0o755);art=root/'artifacts';art.mkdir(mode=0o755);private=root/'private';private.mkdir(mode=0o700);os.chown(private,10001,10001)
 binary=root/'native-retry-trust';shutil.copyfile(a.binary,binary);binary.chmod(0o555)
 repo=pathlib.Path(a.repair_repo)
 for name in ['solution.py','test_solution.py']:
  blob=command(['/usr/bin/setpriv','--reuid=994','--regid=984','--groups=984','/usr/bin/env','-i','PATH=/usr/bin:/bin','HOME=/nonexistent','git','-C',str(repo),'show',COMMIT+':'+name])
  (source/name).write_text(blob);(source/name).chmod(0o444)
 shutil.copyfile(a.holdout,source/'heldout.py');(source/'heldout.py').chmod(0o444)
 shutil.copyfile(a.provenance,source/'provenance.json');(source/'provenance.json').chmod(0o444)
 python=pathlib.Path('/usr/bin/python3').resolve();stdlib=pathlib.Path('/usr/lib')/('python'+'.'.join(map(str,__import__('sys').version_info[:2])))
 runtime={}
 for p in [python,pathlib.Path('/usr/bin/unshare'),pathlib.Path('/usr/bin/setpriv'),pathlib.Path('/usr/bin/timeout')]:
  runtime[str(p)]=sha(p);runtime[str(p.resolve())]=sha(p.resolve())
 for p in stdlib.rglob('*'):
  if p.is_file():
   resolved=p.resolve();runtime[str(resolved)]=sha(resolved)
 key=secrets.token_bytes(32);keyfile=private/'signing-key';keyfile.write_bytes(key);keyfile.chmod(0o400);os.chown(keyfile,10001,10001)
 network='hermes-learning-native-proof-'+secrets.token_hex(5);container=network+'-pg';created=False
 report={'status':'started','provider_calls':0,'production_changed':False,'existing_pending_database_changed':False,'negative_tests':{}}
 def save():(root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 def docker(*args,**kw):return command(D+list(args),**kw)
 def sql(s):return docker('exec',container,'psql','-U','postgres','-d','hermes_learning_fixture','-At','-v','ON_ERROR_STOP=1','-c',s)
 def counts():return json.loads(sql("SELECT json_build_object('bindings',(SELECT count(*) FROM learning_actor_tokens),'grants',(SELECT count(*) FROM learning_curator_grants),'evidence',(SELECT count(*) FROM learning_verified_evidence),'audit',(SELECT count(*) FROM audit_events),'outbox',(SELECT count(*) FROM audit_outbox));"))
 def invoke(op,policyfile,proof,expect=0):
  cmd=[str(binary),op,str(policyfile),str(keyfile),str(proof)]
  if op=='import':cmd+= [str(private/'database-url')];cmd=['/usr/bin/setpriv','--reuid=10001','--regid=10001','--groups=10001',*cmd]
  r=subprocess.run(cmd,capture_output=True,text=True,env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'},timeout=120)
  if (r.returncode==0)!=(expect==0):
   labels=['admission path required','pinned input changed','independent native test process failed','original five tests failed','independent 259 holdout failed','delivery target mismatch','database URL retarget denied','runtime alias']
   report['failed_operation']={'operation':op,'exit_code':r.returncode,'recognized_error_labels':[v for v in labels if v in r.stderr]}
   raise RuntimeError('native trust '+op+' unexpected outcome')
  return r.returncode
 try:
  docker('network','create','--internal',network)
  pgpass=secrets.token_hex(24);secret=private/'pg-password';secret.write_text(pgpass+'\n');secret.chmod(0o400)
  created=True;docker('run','-d','--pull=never','--name',container,'--network',network,'--tmpfs','/var/lib/postgresql/data:rw,size=768m','-e','POSTGRES_PASSWORD_FILE=/run/secrets/password','-e','POSTGRES_DB=hermes_learning_fixture','--mount','type=bind,src='+str(secret)+',dst=/run/secrets/password,readonly',a.pg_image)
  for _ in range(60):
   r=subprocess.run(D+['exec',container,'pg_isready','-U','postgres','-d','hermes_learning_fixture'],capture_output=True)
   if not r.returncode:break
   time.sleep(1)
  else:raise RuntimeError('isolated PG readiness failed')
  info=json.loads(docker('inspect',container))[0];ip=info['NetworkSettings']['Networks'][network]['IPAddress']
  dbfile=private/'database-url';dbfile.write_text('postgres://postgres:'+pgpass+'@'+ip+':5432/hermes_learning_fixture\n');dbfile.chmod(0o400);os.chown(dbfile,10001,10001)
  docker('run','--rm','--pull=never','--network',network,'--read-only','--cap-drop=ALL','--user','10001:10001','--security-opt','no-new-privileges','--mount','type=bind,src='+str(dbfile)+',dst=/run/secrets/database-url,readonly','-e','DATABASE_URL_FILE=/run/secrets/database-url','--entrypoint','/usr/local/bin/clawforge-migrate',a.runtime_image)
  owner=str(uuid.uuid4());curator=str(uuid.uuid4())
  for identity,scopes in [(owner,['agent:learning:read','agent:learning:propose']),(curator,['agent:learning:curate'])]:
   token=secrets.token_urlsafe(36);sql("INSERT INTO agent_tokens(id,name,token_hash,token_prefix,scopes,expires_at) VALUES ('"+identity+"','native-proof-fixture','"+hashlib.sha256(token.encode()).hexdigest()+"','"+token[:8]+"','"+json.dumps(scopes)+"'::jsonb,now()+interval '1 hour');")
  instance=json.loads(sql("SELECT json_build_object('cluster_system_identifier',(SELECT system_identifier::text FROM pg_control_system()),'database_oid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()));"))
  actual_network=json.loads(docker('network','inspect',network))[0];assert actual_network['Internal'] is True and not info['HostConfig']['PortBindings']
  delivery={'kind':'isolated-native-retry','network_internal':actual_network['Internal'],'published_ports':bool(info['HostConfig']['PortBindings']),'network':network,'network_id':info['NetworkSettings']['Networks'][network]['NetworkID'],'database_host':ip,'database_port':5432,'database_name':'hermes_learning_fixture','runtime_image_digest':a.runtime_image,'importer_sha256':sha(binary),**instance}
  deliveryfile=root/'delivery.json';deliveryfile.write_text(json.dumps(delivery,indent=2)+'\n')
  policy={'version':1,'expires_at':int(time.time())+1800,'repository':'hermes-native-acceptance-fixtures','commit':COMMIT,'workspace':str(source),'artifacts':str(art),'python':str(python),'runtime_sha256':runtime,'delivery':str(deliveryfile),'delivery_sha256':sha(deliveryfile),'database_host':ip,'database_port':5432,'database_name':'hermes_learning_fixture',**instance,'runtime_image_digest':a.runtime_image,'importer_sha256':sha(binary),'owner_token':owner,'owner_actor':owner,'curator_token':curator,'curator_actor':curator}
  policyfile=root/'policy.json';policyfile.write_text(json.dumps(policy,indent=2)+'\n');proof=art/'proof.json';save()
  invoke('produce',policyfile,proof);report['actual_independent_tests']={'unit_passed':5,'heldout_passed':259,'uid':994,'new_network_namespace':True}
  for file in art.iterdir():os.chown(file,10001,10001);file.chmod(0o400)
  invoke('verify',policyfile,proof);baseline=counts();sealed=json.loads(proof.read_text());original_artifact=art/sealed['proof']['artifact'];artifact_before=original_artifact.read_bytes()
  # A correctly authenticated but false-success result must still be denied.
  false=json.loads(artifact_before);false['heldout_passed']=258;original_artifact.write_text(json.dumps(false));wrong=sealed.copy();wrong['proof']=dict(sealed['proof']);wrong['proof']['artifact_sha256']=sha(original_artifact);wrong['mac']=hmac.new(key,DOMAIN+json.dumps(wrong['proof'],separators=(',',':')).encode(),hashlib.sha256).hexdigest();badproof=art/'false-success-proof.json';badproof.write_text(json.dumps(wrong));badproof.chmod(0o400);os.chown(badproof,10001,10001)
  invoke('import',policyfile,badproof,1);assert counts()==baseline;report['negative_tests']['authenticated_false_success']=True
  original_artifact.write_bytes(artifact_before)
  # Same database URL, wrong approved instance: authorized writing transaction denies.
  wrongpolicy=dict(policy);wrongdelivery=dict(delivery);wrongpolicy['database_oid']+=1;wrongdelivery['database_oid']+=1
  wrongfile=root/'wrong-delivery.json';wrongfile.write_text(json.dumps(wrongdelivery));wrongpolicy['delivery']=str(wrongfile);wrongpolicy['delivery_sha256']=sha(wrongfile);wrongp=root/'wrong-policy.json';wrongp.write_text(json.dumps(wrongpolicy))
  wrong=dict(sealed);wrong['proof']=dict(sealed['proof']);wrong['proof']['policy_sha256']=sha(wrongp);wrong['mac']=hmac.new(key,DOMAIN+json.dumps(wrong['proof'],separators=(',',':')).encode(),hashlib.sha256).hexdigest();wrongproof=art/'wrong-instance-proof.json';wrongproof.write_text(json.dumps(wrong));wrongproof.chmod(0o400);os.chown(wrongproof,10001,10001)
  invoke('import',wrongp,wrongproof,1);assert counts()==baseline;report['negative_tests']['wrong_instance_zero_writes']=True
  # Mutated policy target cannot retarget the existing genuine proof.
  retarget=dict(policy);retarget['database_host']='192.168.255.254';retargetfile=root/'retarget-policy.json';retargetfile.write_text(json.dumps(retarget));invoke('import',retargetfile,proof,1);assert counts()==baseline;report['negative_tests']['retarget_zero_writes']=True
  invoke('import',policyfile,proof);after=counts();assert after['bindings']==2 and after['grants']==1 and after['evidence']==1
  invoke('import',policyfile,proof);assert counts()==after
  report.update({'status':'passed','actual_import':True,'replay_idempotent':True,'counts':after,'artifact_sha256':sealed['proof']['artifact_sha256'],'artifact':str(original_artifact),'old_result_provenance_only':True,'existing_cargo_cli_unchanged':True});save();print(json.dumps(report))
 except BaseException as exc:
  report.update({'status':'failed','error_type':type(exc).__name__});save();raise
 finally:
  if created:subprocess.run(D+['rm','-f',container],capture_output=True)
  subprocess.run(D+['network','rm',network],capture_output=True)
  report['fixture_cleaned']=True;save()
if __name__=='__main__':main()
