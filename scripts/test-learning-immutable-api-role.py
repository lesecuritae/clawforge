#!/usr/bin/env python3
"""Real isolated provisioned API-role regression; no production/ports/schema changes."""
import argparse,datetime,json,os,pathlib,secrets,subprocess,tempfile,time
D=['docker','-H','unix:///var/run/docker.sock']
def docker(*args):
 r=subprocess.run(D+list(args),capture_output=True,text=True)
 if r.returncode:raise RuntimeError('fixture docker operation '+args[0]+' failed')
 return r.stdout

def main():
 p=argparse.ArgumentParser();p.add_argument('--pg-image',required=True);p.add_argument('--runtime-image',required=True);p.add_argument('--target-dir',required=True);p.add_argument('--report',required=True);a=p.parse_args()
 repo=pathlib.Path(__file__).resolve().parent.parent
 stamp=secrets.token_hex(6);net='learning-immutable-regression-'+stamp;pg=net+'-pg';created=[];network=False
 report={'status':'started','provider_calls':0,'production_changed':False,'migration_changes':False,'public_ports':False}
 with tempfile.TemporaryDirectory(prefix='learning-immutable-regression-') as tmp:
  root=pathlib.Path(tmp);passwords={name:secrets.token_hex(24) for name in ['postgres','api','worker','correlation','security_engine','policy_engine','incidents','executor','backup']}
  def secret(name,value):
   f=root/name;f.write_text(value+'\n');f.chmod(0o444);return f
  def mount(name):return ['--mount','type=bind,src='+str(root/name)+',dst=/run/test-secrets/'+name+',readonly']
  def save():
   dest=pathlib.Path(a.report);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(json.dumps(report,indent=2)+'\n');dest.chmod(0o600)
  try:
   secret('postgres_password',passwords['postgres'])
   for role in passwords:
    if role!='postgres':secret('database_'+role+'_password',passwords[role])
   docker('network','create','--internal',net);network=True
   created.append(pg)
   docker('run','-d','--pull=never','--name',pg,'--network',net,'--tmpfs','/var/lib/postgresql/data:rw,size=768m','-e','POSTGRES_DB=clawforge_test','-e','POSTGRES_PASSWORD_FILE=/run/test-secrets/postgres_password',*mount('postgres_password'),a.pg_image)
   for _ in range(60):
    if subprocess.run(D+['exec',pg,'pg_isready','-U','postgres','-d','clawforge_test'],capture_output=True).returncode==0:break
    time.sleep(1)
   else:raise RuntimeError('fixture PostgreSQL readiness failed')
   info=json.loads(docker('inspect',pg))[0];assert not info['HostConfig']['PortBindings']
   ip=info['NetworkSettings']['Networks'][net]['IPAddress'];assert json.loads(docker('network','inspect',net))[0]['Internal']
   owner='postgres://postgres:'+passwords['postgres']+'@'+ip+':5432/clawforge_test'
   secret('migration_url','postgres://postgres:'+passwords['postgres']+'@'+pg+':5432/clawforge_test')
   migration=net+'-migration';created.append(migration)
   docker('run','--rm','--pull=never','--name',migration,'--network',net,'--read-only','--cap-drop=ALL','--security-opt','no-new-privileges','--user','10001:10001',*mount('migration_url'),'-e','DATABASE_URL_FILE=/run/test-secrets/migration_url','--entrypoint','/usr/local/bin/clawforge-migrate',a.runtime_image)
   roles=net+'-roles';created.append(roles)
   mounts=sum([mount(n.name) for n in root.glob('*_password')],[])
   docker('run','--rm','--pull=never','--name',roles,'--network',net,*mounts,'--mount','type=bind,src='+str(repo/'scripts/provision-db-roles.sh')+',dst=/provision.sh,readonly','-e','PGHOST='+pg,'-e','POSTGRES_USER=postgres','-e','POSTGRES_DB=clawforge_test','-e','CLAWFORGE_POSTGRES_SECRET_FILE=/run/test-secrets/postgres_password',*[v for role in passwords if role!='postgres' for v in ['-e','CLAWFORGE_DATABASE_'+role.upper()+'_PASSWORD_SECRET_FILE=/run/test-secrets/database_'+role+'_password']],'--entrypoint','/bin/sh',a.pg_image,'/provision.sh')
   env=os.environ.copy();env.update({'CARGO_TARGET_DIR':a.target_dir,'CLAWFORGE_LEARNING_TEST_DATABASE_URL':owner,'CLAWFORGE_TEST_API_DATABASE_URL':'postgres://clawforge_api:'+passwords['api']+'@'+ip+':5432/clawforge_test'})
   result=subprocess.run(['cargo','test','--offline','-p','clawforge-storage','--test','learning','immutable_api_role_serializes_lesson_transitions_without_update_grants','--','--ignored','--exact','--nocapture'],cwd=repo,env=env,capture_output=True,text=True,timeout=600)
   output=result.stdout+'\n'+result.stderr
   for value in passwords.values():output=output.replace(value,'[REDACTED]')
   log=pathlib.Path(a.report).with_suffix('.log');log.write_text(output);log.chmod(0o600)
   report.update({'test_exit_code':result.returncode,'log':str(log),'api_role':'clawforge_api','migration_version':56})
   if result.returncode!=0:raise RuntimeError('actual API-role regression failed; redacted log retained')
   assert '1 passed; 0 failed' in result.stdout
   report.update({'status':'passed','tested_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'old_for_update_sqlstate':'42501','content_update_sqlstate':'42501','lesson_update_permission':False,'shared_lock_blocks_competing_revision':True,'concurrent_revision_and_review_serialization':True,'record_retry_idempotent':True})
  except BaseException as exc:
   report.update({'status':'failed','error_type':type(exc).__name__});raise
  finally:
   report['cleanup_containers']={name:subprocess.run(D+['rm','-f',name],capture_output=True).returncode==0 for name in reversed(created)}
   report['cleanup_network']=not network or subprocess.run(D+['network','rm',net],capture_output=True).returncode==0
   save()
  print(json.dumps(report))
if __name__=='__main__':main()
