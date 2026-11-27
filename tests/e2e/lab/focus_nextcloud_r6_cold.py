"""Only normalize this case's Office failed flag AFTER its own STOP. No broad reset."""
import inspect
from focus_nextcloud_r6_wake import device


def may_clear(prior,claimed,post,stop_us):
    return (prior.get('ActiveState')=='inactive' and claimed is not None
            and claimed.get('ActiveState')=='active' and int(claimed.get('MainPID') or 0)>0
            and bool(claimed.get('InvocationID')) and post.get('InvocationID')==claimed['InvocationID']
            and post.get('ActiveState')=='failed' and post.get('SubState')=='failed'
            and post.get('Result')=='exit-code' and post.get('ExecMainStatus')=='137'
            and int(post.get('MainPID') or 0)==0
            and int(post.get('ExecMainExitTimestampMonotonic') or 0)>=stop_us
            and post.get('UnitFileState')==prior.get('UnitFileState'))


FIELDS='ActiveState,SubState,UnitFileState,MainPID,InvocationID,Result,ExecMainStatus,ExecMainExitTimestampMonotonic'
CLAIM="""
import json,subprocess
p=subprocess.run(['systemctl','--user','show','nextcloud-office.service','--property=FIELDS'],capture_output=True,timeout=30)
assert p.returncode==0
print(json.dumps(dict(x.split('=',1) for x in p.stdout.decode().splitlines() if '=' in x)))
""".replace('FIELDS',FIELDS)
STOP=inspect.getsource(may_clear)+r'''
import json,subprocess,sys,time
q=json.load(sys.stdin)
def status():
 p=subprocess.run(['systemctl','--user','show','nextcloud-office.service','--property=FIELDS'],capture_output=True,timeout=30)
 assert p.returncode==0
 return dict(x.split('=',1) for x in p.stdout.decode().splitlines() if '=' in x)
pre=status();start=time.monotonic_ns()//1000
units=['nextcloud-cron.timer','nextcloud-cron.service','nextcloud.target','nextcloud-app.service','nextcloud-db.service',
 'nextcloud-office.service','nextcloud-gateway.service','nextcloud-redis.service']
p=subprocess.run(['systemctl','--user','stop',*units],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=180)
assert p.returncode==0
post=status();cleared=False
if post.get('ActiveState')=='failed':
 assert q['claimed'] is not None and pre.get('InvocationID')==q['claimed'].get('InvocationID')
 assert pre.get('ActiveState')=='active' and int(pre.get('MainPID') or 0)>0
 assert may_clear(q['prior'],q['claimed'],post,start)
 # Re-read the complete exact failure tuple immediately before the single reset.
 assert status()==post
 p=subprocess.run(['systemctl','--user','reset-failed','nextcloud-office.service'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
 assert p.returncode==0;cleared=True
assert status().get('ActiveState')=='inactive'
print(json.dumps({'status':'stopped','only_owned_office_failed_flag_cleared':cleared,'stop_monotonic_us':start,
 'office_before_stop':pre,'office_after_stop':post}))
'''
STOP=STOP.replace('FIELDS',FIELDS)


def stop(prior,claimed):
    return device(STOP,{'prior':prior,'claimed':claimed},timeout=240)
