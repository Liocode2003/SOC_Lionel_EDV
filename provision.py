#!/usr/bin/env python3
"""Initialisation d'un SOC neuf. Aucun identifiant de l'ancienne VM n'est utilisé."""
import base64
import copy
import http.cookiejar
import ipaddress
import json
from pathlib import Path
import secrets
import ssl
import time
import uuid
import urllib.request
import urllib.error
from urllib.parse import quote
import xml.etree.ElementTree as ET

class ProvisionError(RuntimeError): pass
class API:
    def __init__(self,base,key=None,basic=None,local_tls=False):
        self.base=base.rstrip('/');self.key=key;self.basic=basic
        context=ssl._create_unverified_context() if local_tls else ssl.create_default_context()
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),urllib.request.HTTPSHandler(context=context))
    def call(self,method,path,data=None,text=False):
        headers={'Accept':'application/json','Content-Type':'application/json'}
        if self.key:headers['Authorization']='Bearer '+self.key
        if self.basic:headers['Authorization']='Basic '+base64.b64encode((':'.join(self.basic)).encode()).decode()
        req=urllib.request.Request(self.base+path,data=None if data is None else json.dumps(data).encode(),headers=headers,method=method)
        try:
            with self.opener.open(req,timeout=120) as r: raw=r.read().decode()
        except urllib.error.HTTPError as e:raise ProvisionError('HTTP '+str(e.code)+' sur '+path.split('?')[0]) from None
        if text:return raw.strip('"\n ')
        if not raw:return {}
        try: result=json.loads(raw)
        except ValueError:raise ProvisionError('Réponse JSON inattendue : '+path) from None
        if isinstance(result,dict) and result.get('success') is False:raise ProvisionError('API ayant refusé : '+path)
        return result

def wait(label,check,timeout=1200):
    end=time.monotonic()+timeout;last=None
    while time.monotonic()<end:
        try:
            result=check()
            if result is not False:return result
        except Exception as e:last=e
        print('Initialisation : '+label+'…',flush=True);time.sleep(10)
    raise ProvisionError('Délai dépassé : '+label+' ('+type(last).__name__+')')

def cortex(cfg, saved, save):
    api=API('http://127.0.0.1:9001')
    wait('Cortex',lambda:api.call('GET','/api/status'))
    # Le contexte init est utilisable seulement si aucun utilisateur n'existe.
    if not saved.get('cortex_admin_cree'):
        api.call('POST','/api/maintenance/migrate',{})
        api.call('POST','/api/user',{'login':'soc-superadmin','name':'Administrateur SOC','roles':['superadmin'],'password':cfg['cortex_admin_password']})
        saved['cortex_admin_cree']=True;save()
    api.basic=('soc-superadmin',cfg['cortex_admin_password'])
    if not saved.get('cortex_org_creee'):
        api.call('POST','/api/organization',{'name':'SOC','description':'Organisation de laboratoire'})
        saved['cortex_org_creee']=True;save()
    if not saved.get('cortex_user_cree'):
        api.call('POST','/api/user',{'login':'soc-api','name':'Intégrations SOC','roles':['read','analyze','orgadmin'],'organization':'SOC','password':cfg['cortex_user_password']})
        saved['cortex_user_cree']=True;save()
    api.basic=('soc-api',cfg['cortex_user_password'])
    if not saved.get('cortex_key'):
        saved['cortex_key']=api.call('POST','/api/user/soc-api/key/renew',{},text=True);save()
    api.basic=None;api.key=saved['cortex_key']
    definitions=api.call('GET','/api/analyzerdefinition')
    if not isinstance(definitions,list):raise ProvisionError('Liste des analyseurs Cortex inattendue.')
    if 'analyzers' not in saved:saved['analyzers']=[]
    for name,key in [('VirusTotal_GetReport',cfg['virustotal_key']),('AbuseIPDB',cfg['abuseipdb_key'])]:
        if any(a['name']==name for a in saved['analyzers']):continue
        choices=[d for d in definitions if d.get('name')==name]
        if not choices:raise ProvisionError('Définition analyseur absente : '+name)
        d=sorted(choices,key=lambda x:x.get('version',''))[-1];definition_id=d.get('id') or d.get('_id')
        if not definition_id:raise ProvisionError('Identifiant définition absent : '+name)
        conf={'key':key,'check_tlp':True,'max_tlp':2,'check_pap':True,'max_pap':2,'auto_extract':False}
        if name=='VirusTotal_GetReport':
            # Pas d'upload ni de rescan automatique du hash.
            conf.update({'rescan_hash_older_than_days':0,'download_sample':False,'download_sample_if_highlighted':False})
        a=api.call('POST','/api/organization/analyzer/'+quote(definition_id,safe=''),{'name':name,'configuration':conf})
        aid=a.get('id') or a.get('_id')
        if not aid:raise ProvisionError('Activation analyseur non confirmée : '+name)
        saved['analyzers'].append({'id':aid,'name':name});save()
    return {'analyseurs':saved['analyzers']}

def thehive(cfg,saved,save):
    api=API('http://127.0.0.1:9000',basic=('admin@thehive.local',cfg['thehive_admin_password'] if saved.get('hive_password_change') else 'secret'))
    wait('TheHive',lambda:api.call('GET','/api/status'))
    if not saved.get('hive_password_change'):
        api.call('POST','/api/v1/user/admin%40thehive.local/password/change',{'currentPassword':'secret','password':cfg['thehive_admin_password']})
        saved['hive_password_change']=True;save();api.basic=('admin@thehive.local',cfg['thehive_admin_password'])
    if not saved.get('hive_org_creee'):
        api.call('POST','/api/v1/organisation',{'name':'SOC','description':'Laboratoire SOC autonome'})
        saved['hive_org_creee']=True;save()
    if not saved.get('hive_user_cree'):
        api.call('POST','/api/v1/user',{'login':'soc@soc.local','name':'Analyste SOC','organisation':'SOC','profile':'org-admin','password':cfg['thehive_user_password']})
        saved['hive_user_cree']=True;save()
    if not saved.get('thehive_key'):
        saved['thehive_key']=api.call('POST','/api/v1/user/soc%40soc.local/key/renew',{},text=True);save()
    return {'organisation':'SOC','utilisateur':'soc@soc.local'}

def misp(cfg,saved,save):
    api=API('https://127.0.0.1:8443',local_tls=True)
    original=api.call
    # MISP attend la clé brute, contrairement aux Bearer des autres services.
    api.opener.addheaders=[('Authorization',cfg['misp_key'])]
    wait('API MISP',lambda:api.call('GET','/servers/getVersion'))
    api.call('POST','/feeds/loadDefaultFeeds',{})
    feeds=api.call('GET','/feeds/index')
    if not isinstance(feeds,list):raise ProvisionError('Liste feeds MISP inattendue.')
    selected=[f.get('Feed',f) for f in feeds]
    selected=[f for f in selected if str(f.get('id')) in cfg['misp_feed_ids']]
    if len(selected)!=len(cfg['misp_feed_ids']):raise ProvisionError('Un des feeds configurés est absent de MISP.')
    result=[]
    for f in selected:
        fid=str(f['id'])
        api.call('POST','/feeds/edit/'+fid,{'Feed':{'enabled':True,'caching_enabled':True}})
        api.call('POST','/feeds/fetchFromFeed/'+fid,{})
        result.append({'id':fid,'etat':'synchronisation demandee'})
    # Absence de feeds explicitement sélectionnés : ne prétend pas avoir synchronisé.
    return {'api':'authentifiee','feeds':result,'limite':'Les imports peuvent continuer en tâche de fond.'}

def render_workflow(template,wid,child,hook,app,env,config,code):
    w=copy.deepcopy(template)
    ids={w['id']:wid}
    for section in ('actions','branches','triggers'):
        for node in w.get(section,[]):ids[node['id']]=str(uuid.uuid4())
    for t in w.get('triggers',[]):
        if t['app_name']=='Webhook':ids[t['id']]=hook
    def visit(x):
        if isinstance(x,dict):return {k:visit(v) for k,v in x.items()}
        if isinstance(x,list):return [visit(v) for v in x]
        if isinstance(x,str):return ids.get(x,x)
        return x
    w=visit(w);w['id']=wid;w['owner']='';w['org_id']='';w['execution_org']={};w['sharing']='private';w['public']=False
    w['workflow_variables']=[{'name':'SOC_CONFIG','value':json.dumps(config),'description':'Configuration privée générée à l’installation.'}]
    stages={'configuration':'check_config','doublons':'dedup','priorite':'prioritize','enrichissement':'enrich','transmettre':'publish','accord_enregistre':'audit','notification':'notify'}
    for a in w['actions']:
        a['environment']=env;a['app_id']=app['id'];a['app_version']=app['app_version'];a['errors']=[]
        a['parameters']=[{'name':'code','value':code+'\n\nrun('+repr(stages[a['label']])+')\n','variant':'STATIC_VALUE','required':True}]
    for t in w.get('triggers',[]):
        t['environment']=env;t['errors']=[]
        if t['app_name']=='Webhook':
            t['status']='running'
            for p in t.get('parameters',[]):
                if p['name']=='url':p['value']=config['shuffle_frontend']+'/api/v1/hooks/webhook_'+hook
                if p['name']=='tmp':p['value']='webhook_'+hook
        elif t['app_name']=='User Input':
            for p in t.get('parameters',[]):
                if p['name']=='subflow':p['value']=child
    w['errors']=[];w['is_valid']=True
    return w

def shuffle(cfg,saved,save,templates):
    api=API('http://127.0.0.1:5001',key=cfg['shuffle_key'])
    envs=wait('API Shuffle',lambda:api.call('GET','/api/v1/getenvironments'))
    if isinstance(envs,dict):envs=envs.get('environments',[])
    env=next((x['Name'] if 'Name' in x else x['name'] for x in envs if str(x.get('type','')).lower() in ('onprem','') and not x.get('archived')),None)
    if not env:raise ProvisionError('Aucun environnement local actif dans Shuffle.')
    apps=api.call('GET','/api/v1/apps')
    if isinstance(apps,dict):apps=apps.get('apps',[])
    choices=[a for a in apps if a.get('name','').lower().replace('_',' ')=='shuffle tools' and any(x.get('name')=='execute_python' for x in a.get('actions',[]))]
    if not choices:
        api.call('POST','/api/v1/apps/download_remote',{'url':'https://github.com/Shuffle/python-apps','force_update':False})
        apps=api.call('GET','/api/v1/apps');apps=apps.get('apps',[]) if isinstance(apps,dict) else apps
        choices=[a for a in apps if a.get('name','').lower().replace('_',' ')=='shuffle tools' and any(x.get('name')=='execute_python' for x in a.get('actions',[]))]
    if not choices:raise ProvisionError('Shuffle Tools execute_python introuvable après téléchargement.')
    app=next((a for a in choices if a.get('app_version')=='1.2.0'),choices[0])
    api.call('GET','/api/v1/apps/'+app['id']+'/activate')
    for name in ('principal','notification'):
        if name not in saved:
            r=api.call('POST','/api/v1/workflows',{'name':'SOC autonome — '+name,'description':'Workflow généré sur une instance neuve.'})
            wid=r.get('id') or r.get('workflow_id')
            if not wid:raise ProvisionError('Création du workflow non confirmée : '+name)
            saved[name]=wid;save()
    if 'hook' not in saved:saved['hook']=str(uuid.uuid4());save()
    mainconfig={'thehive_url':'http://thehive:9000','thehive_frontend':'http://'+cfg['ip']+':9000','thehive_key':saved['thehive_key'],
        'misp_url':'https://misp:443','misp_key':cfg['misp_key'],'cortex_url':'http://cortex:9001','cortex_key':saved['cortex_key'],
        'cortex_analyzer_ids':[a['id'] for a in saved['analyzers']],'shuffle_frontend':'http://'+cfg['ip']+':3001','verify_tls':False}
    mailconfig={**{k:cfg[k] for k in ('smtp_host','smtp_port','smtp_username','smtp_password','recipient')},'shuffle_frontend':mainconfig['shuffle_frontend']}
    code=(templates/'workflow_code.py').read_text()
    for name,config in [('notification',mailconfig),('principal',mainconfig)]:
        template=json.loads((templates/(name+'.json')).read_text())
        w=render_workflow(template,saved[name],saved['notification'],saved['hook'],app,env,config,code)
        current=api.call('GET','/api/v1/workflows/'+w['id'])
        for field in ('owner','org_id','execution_org'):
            if field in current:w[field]=current[field]
        api.call('PUT','/api/v1/workflows/'+w['id'],w)
        live=api.call('GET','/api/v1/workflows/'+w['id'])
        if len(live.get('actions',[]))!=len(w['actions']):raise ProvisionError('Relecture des actions incomplète.')
    live=api.call('GET','/api/v1/workflows/'+saved['principal'])
    api.call('POST','/api/v1/hooks',{'name':'Wazuh entrant','type':'webhook','id':saved['hook'],'workflow':saved['principal'],'start':live['start'],'environment':env,'auth':''})
    return {'workflows_crees':[saved['principal'],saved['notification']],'hook':saved['hook'],'environment':env}

def decode(value):
    for _ in range(3):
        if isinstance(value,dict):return value
        if not isinstance(value,str):return {}
        try:value=json.loads(value)
        except ValueError:return {}
    return {}

def integration_test(cfg,saved,save,timeout=600):
    api=API('http://127.0.0.1:5001',key=cfg['shuffle_key'])
    if not saved.get('test_execution'):
        source='SOC-INSTALL-'+uuid.uuid4().hex[:12]
        alert={'title':'TEST INSTALLATION SOC — '+source,'level':12,'agent':'TEST-INSTALLATION','rule_id':'100211','timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'full_alert':{'id':source,'manager':{'name':'SOC-AUTONOME'},'data':{'src_ip':'1.1.1.1'}}}
        r=api.call('POST','/api/v1/workflows/'+saved['principal']+'/execute',{'execution_argument':json.dumps(alert)})
        if not r.get('execution_id') or not r.get('authorization'):raise ProvisionError('Identifiants de suivi du test absents.')
        saved['test_execution']={k:r[k] for k in ('execution_id','authorization')};saved['test_source']=source;save()
    end=time.monotonic()+timeout;last={}
    while time.monotonic()<end:
        run=api.call('POST','/api/v1/streams/results',saved['test_execution'])
        stages={}
        for item in run.get('results') or []:
            label=item.get('action',{}).get('label');raw=decode(item.get('result'));msg=decode(raw.get('message',raw));stages[label]=msg
            if msg.get('ok') is False:raise ProvisionError('Test de bout en bout en échec : '+str(label))
            if label=='enrichissement':
                for o in msg.get('observables',[]):
                    if o.get('misp',{}).get('status')!='ok':raise ProvisionError('Recherche MISP du test non confirmée.')
                    for c in o.get('cortex',[]):
                        if c.get('status') not in ('Success','non_analyse','non_applicable'):raise ProvisionError('Analyse Cortex du test non confirmée.')
            if label=='validation_analyste':
                sub=decode(raw.get('subflow'))
                if sub.get('execution_id') and sub.get('authorization'):
                    child=api.call('POST','/api/v1/streams/results',{k:sub[k] for k in ('execution_id','authorization')})
                    for item2 in child.get('results') or []:
                        n=decode(decode(item2.get('result')).get('message'))
                        if n.get('ok') is False:raise ProvisionError('Notification SMTP en échec.')
                        if n.get('mail_envoye') or n.get('deja_envoye'):
                            required={'configuration','doublons','priorite','enrichissement','transmettre'}
                            if not required.issubset(stages):continue
                            if not stages['transmettre'].get('thehive_id'):raise ProvisionError('Identifiant alerte TheHive absent.')
                            return {'source_id':saved['test_source'],'thehive_id':stages['transmettre']['thehive_id'],'etapes':sorted(required),'smtp':'mail accepté par le serveur','decision_humaine':'en attente ; ouvrir le courriel','limite':'La réception et le clic humain ne sont pas simulés.'}
        if run.get('status') in ('ABORTED','FAILURE'):raise ProvisionError('Exécution du test interrompue/en échec.')
        print('Test en cours : '+str(run.get('status','inconnu')),flush=True);time.sleep(10)
    raise ProvisionError('Test non confirmé dans le délai ; conserver son exécution, ne pas multiplier les essais.')
