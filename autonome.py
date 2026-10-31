#!/usr/bin/env python3
"""Installation et configuration d'un laboratoire SOC neuf, sans VM source."""
import argparse
import fcntl
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape
import infrastructure as infra
import provision as prov

HERE=Path(__file__).resolve().parent
ROOT=Path('/opt/soc/autonome')

def save(path,obj):infra.dump(path,obj)
def secret():return secrets.token_hex(24)+'Aa1!'
def ask_config():
    ip=input('Adresse IPv4 de cette nouvelle VM SOC : ').strip();addr=ipaddress.IPv4Address(ip)
    if addr.is_loopback or addr.is_unspecified:raise RuntimeError('Utiliser l’IP réseau de la VM, pas une adresse de boucle locale.')
    iface=input('Interface réseau Suricata (exemple ens33) : ').strip()
    vt=getpass.getpass('Clé API VirusTotal : ').strip()
    abuse=getpass.getpass('Clé API AbuseIPDB : ').strip()
    host=input('Serveur SMTP [smtp.gmail.com] : ').strip() or 'smtp.gmail.com'
    port=int(input('Port SMTP STARTTLS [587] : ').strip() or '587')
    if port==465:raise RuntimeError('Ce modèle utilise STARTTLS, généralement sur le port 587 ; SMTPS 465 non pris en charge.')
    username=input('Compte SMTP : ').strip();pw=getpass.getpass('Mot de passe SMTP/application : ').strip()
    recipient=input('Adresse mail de l’analyste : ').strip()
    targets=input('IP à préparer dans Greenbone, séparées par des virgules (vide : aucune cible) : ').strip()
    targets=[str(ipaddress.ip_address(t.strip())) for t in targets.split(',') if t.strip()]
    feeds=input('IDs des feeds MISP à activer [1,2] : ').strip() or '1,2'
    feedids=[str(int(x.strip())) for x in feeds.split(',') if x.strip()]
    if not vt or not abuse or not username or not pw or '@' not in recipient:raise RuntimeError('Clés API et paramètres SMTP requis pour la chaîne complète.')
    if not Path('/sys/class/net',iface).exists():raise RuntimeError('Interface réseau inexistante.')
    cfg=dict(ip=ip,interface=iface,virustotal_key=vt,abuseipdb_key=abuse,smtp_host=host,smtp_port=port,smtp_username=username,smtp_password=pw,recipient=recipient,targets=targets,misp_feed_ids=feedids,
        shuffle_key=str(uuid.uuid4()),misp_key=secrets.token_hex(20))
    for name in ('shuffle_password','thehive_admin_password','thehive_user_password','cortex_admin_password','cortex_user_password','wazuh_admin_password','wazuh_dashboard_password','wazuh_api_password','greenbone_password','mysql_password','mysql_root_password','misp_password','redis_password'):
        cfg[name]=secret()
    return cfg

def envfile(path):
    result={}
    for line in path.read_text().splitlines():
        if '=' in line and not line.strip().startswith('#'):
            k,v=line.split('=',1);result[k.strip()]=v.strip().strip('"\'')
    return result

def fresh(folder):folder.mkdir(parents=True,mode=0o700,exist_ok=True)

def reuse(folder):
    lock=folder/'compose.lock.json'
    if not lock.exists():return False
    config=json.loads(lock.read_text())
    infra.pin_and_start(folder,config)
    return True

def hive_install(folder,cfg):
    if reuse(folder):return {"reprise":"manifest verrouillé"}
    fresh(folder)
    jobs=folder/'jobs';jobs.mkdir(exist_ok=True);jobs.chmod(0o777)
    hc=folder/'thehive.conf';cc=folder/'cortex.conf'
    infra.write(hc,'play.http.secret.key="'+secrets.token_hex(32)+'"\n'+
        'db.janusgraph { storage.backend=berkeleyje\n storage.directory="/opt/thp/thehive/database"\n index.search.backend=lucene\n index.search.directory="/opt/thp/thehive/index" }\n'+
        'storage { provider=localfs\n localfs.location="/opt/thp/thehive/files" }\n'+
        'auth.providers=[{name=session},{name=basic,realm=thehive},{name=local},{name=key}]\n',0o644)
    infra.write(cc,'play.http.secret.key="'+secrets.token_hex(32)+'"\n'+
        'search { index=cortex\n uri="http://es-cortex:9200" }\nauth.provider=[local]\n'+
        'analyzer.urls=["https://catalogs.download.strangebee.com/latest/json/analyzers.json"]\n'+
        'responder.urls=[]\njob { directory="/tmp/cortex-jobs"\n dockerDirectory="'+str(jobs)+'" }\n'+
        'docker { host="unix:///var/run/docker.sock"\n autoUpdate=false\n container.networkMode="soc_network" }\n',0o644)
    compose={'services':{
        'es-cortex':{'image':'docker.elastic.co/elasticsearch/elasticsearch:7.17.22','hostname':'es-cortex','environment':{'discovery.type':'single-node','xpack.security.enabled':'false','ES_JAVA_OPTS':'-Xms1g -Xmx1g'},'volumes':['es-data:/usr/share/elasticsearch/data'],'ulimits':{'memlock':{'soft':-1,'hard':-1}},'restart':'unless-stopped'},
        'thehive':{'image':'thehiveproject/thehive4:latest','hostname':'thehive','ports':[cfg['ip']+':9000:9000'],'volumes':[str(hc)+':/etc/thehive/application.conf:ro','hive-db:/opt/thp/thehive/database','hive-index:/opt/thp/thehive/index','hive-files:/opt/thp/thehive/files'],'restart':'unless-stopped'},
        'cortex':{'image':'thehiveproject/cortex:3.1.8','hostname':'cortex','environment':{'DOCKER_API_VERSION':'1.44'},'ports':[cfg['ip']+':9001:9001','127.0.0.1:9001:9001'],'volumes':[str(cc)+':/etc/cortex/application.conf:ro','/var/run/docker.sock:/var/run/docker.sock',str(jobs)+':/tmp/cortex-jobs'],'depends_on':['es-cortex'],'restart':'unless-stopped'}},'volumes':{'es-data':{},'hive-db':{},'hive-index':{},'hive-files':{}}}
    # Écoute également en boucle locale pour les API de provisionnement.
    compose['services']['thehive']['ports'].append('127.0.0.1:9000:9000')
    infra.pin_and_start(folder,compose)
    return {'profil':'TheHive 4 laboratoire BerkeleyJE/Lucene + Cortex 3.1.8/Elasticsearch 7.17.22'}

def wazuh_install(folder,cfg):
    if reuse(folder):return {"reprise":"manifest verrouillé"}
    import yaml,bcrypt
    fresh(folder)
    repo=folder/'source';infra.clone('https://github.com/wazuh/wazuh-docker.git',repo,'v4.14.9');wd=repo/'single-node'
    p=wd/'docker-compose.yml';w=yaml.safe_load(p.read_text())
    for svc in w['services'].values():
        env=svc.get('environment',[])
        vals={x.split('=',1)[0]:x.split('=',1)[1] for x in env} if isinstance(env,list) else env
        for k in ('INDEXER_PASSWORD',):
            if k in vals:vals[k]=cfg['wazuh_admin_password']
        if 'DASHBOARD_PASSWORD' in vals:vals['DASHBOARD_PASSWORD']=cfg['wazuh_dashboard_password']
        if 'API_PASSWORD' in vals:vals['API_PASSWORD']=cfg['wazuh_api_password']
        svc['environment']=vals
    infra.write(p,yaml.safe_dump(w))
    users=wd/'config/wazuh_indexer/internal_users.yml';u=yaml.safe_load(users.read_text())
    for name in list(u):
        if name not in ('_meta','admin','kibanaserver'):del u[name]
    for name,password in [('admin',cfg['wazuh_admin_password']),('kibanaserver',cfg['wazuh_dashboard_password'])]:
        u[name]['hash']=bcrypt.hashpw(password.encode(),bcrypt.gensalt()).decode()
    infra.write(users,yaml.safe_dump(u),0o644)
    # Le connecteur Dashboard peut utiliser le fichier wazuh.yml en plus des variables.
    for path in (wd/'config/wazuh_dashboard').glob('*.yml'):
        text=path.read_text().replace('MyS3cr37P450r.*-',cfg['wazuh_api_password'])
        infra.write(path,text,0o644)
    result=infra.install_wazuh(folder,cfg['ip'])
    return {'version':'4.14.9','mots_de_passe':'générés localement','commit':result['commit']}

def misp_install(folder,cfg):
    if reuse(folder):return {"reprise":"manifest verrouillé"}
    fresh(folder);repo=folder/'source';commit=infra.clone('https://github.com/MISP/misp-docker.git',repo)
    if not (repo/'.env').exists():shutil.copy2(repo/'template.env',repo/'.env')
    infra.env_update(repo/'.env',{'BASE_URL':'https://'+cfg['ip']+':8443','NGINX_HTTP_PORT':'8080','NGINX_HTTPS_PORT':'8443','ADMIN_EMAIL':'admin@soc.local','ADMIN_ORG':'SOC','ADMIN_PASSWORD':cfg['misp_password'],'ADMIN_KEY':cfg['misp_key'],'MYSQL_PASSWORD':cfg['mysql_password'],'MYSQL_ROOT_PASSWORD':cfg['mysql_root_password'],'REDIS_PASSWORD':cfg['redis_password'],'DISABLE_PRINTING_PLAINTEXT_CREDENTIALS':'true','TZ':'UTC'})
    c=infra.raw_config(repo,repo/'docker-compose.yml')
    # Alias interne stable, indépendant du nom de service des manifests amont.
    core=next((s for n,s in c['services'].items() if 'misp-core' in n),None)
    if core is None:raise RuntimeError('Service misp-core absent du manifeste officiel.')
    networks=core.setdefault('networks',{})
    if isinstance(networks,list):networks={n:{} for n in networks};core['networks']=networks
    networks['soc_network']={'aliases':['misp']}
    infra.pin_and_start(folder,c)
    return {'commit':commit}

def shuffle_install(folder,cfg):
    if reuse(folder):return {"reprise":"manifest verrouillé"}
    fresh(folder);repo=folder/'source';commit=infra.clone('https://github.com/Shuffle/Shuffle.git',repo)
    pw=secret()
    infra.env_update(repo/'.env',{'SHUFFLE_DEFAULT_USERNAME':'admin@soc.local','SHUFFLE_DEFAULT_PASSWORD':cfg['shuffle_password'],'SHUFFLE_DEFAULT_APIKEY':cfg['shuffle_key'],'SHUFFLE_ENCRYPTION_MODIFIER':secrets.token_hex(32),'SHUFFLE_OPENSEARCH_PASSWORD':pw,'OPENSEARCH_INITIAL_ADMIN_PASSWORD':pw,'SHUFFLE_ORBORUS_EXECUTION_CONCURRENCY':'2','SHUFFLE_ORBORUS_EXECUTION_TIMEOUT':'600','SHUFFLE_CONTAINER_AUTO_CLEANUP':'true','FRONTEND_PORT':'3001','FRONTEND_PORT_HTTPS':'3443','BACKEND_PORT':'5001','BACKEND_HOSTNAME':'shuffle-backend','ENVIRONMENT_NAME':'onprem','TZ':'UTC'})
    c=infra.raw_config(repo,repo/'docker-compose.yml')
    c['services'].pop('shuffle-security',None)
    for name,s in c['services'].items():
        s.pop('build',None)
        if name in ('orborus','backend'):
            s.setdefault('environment',{}).update({'ENVIRONMENT_NAME':'onprem','SHUFFLE_DOCKER_NETWORK':'soc_network','DOCKER_NETWORK':'soc_network','DOCKER_API_VERSION':'1.44'})
        if name=='orborus':s['environment'].update({'SHUFFLE_ORBORUS_EXECUTION_CONCURRENCY':'2','SHUFFLE_ORBORUS_EXECUTION_TIMEOUT':'600','CLEANUP':'true'})
        for mount in s.get('volumes',[]):
            if isinstance(mount,dict) and mount.get('type')=='bind' and mount['source']!='/var/run/docker.sock':
                path=Path(mount['source'])
                if not path.exists():path.mkdir(parents=True)
                if path.is_dir():path.chmod(0o777)
    infra.pin_and_start(folder,c)
    return {'commit':commit}

def greenbone_install(folder,cfg):
    if reuse(folder):return {"reprise":"manifest verrouillé"}
    fresh(folder)
    file=folder/'official.compose.yaml';digest=infra.download('https://greenbone.github.io/docs/latest/_static/compose.yaml',file)
    c=infra.raw_config(folder,file)
    frontend=c['services'].get('nginx') or c['services'].get('gsa')
    if not frontend:raise RuntimeError('Interface Greenbone introuvable.')
    frontend['ports']=[{'target':9392,'published':'9392','host_ip':cfg['ip'],'protocol':'tcp'}]
    infra.pin_and_start(folder,c)
    return {'source_sha256':digest}

def greenbone_setup(folder,cfg,saved,persist):
    cmd=infra.compose_cmd(folder)
    infra.run(cmd+['exec','-T','-u','gvmd','gvmd','gvmd','--user=admin','--new-password='+cfg['greenbone_password']])
    def gmp(xml):
        raw=infra.run(cmd+['run','--rm','-T','gvm-tools','gvm-cli','--gmp-username','admin','--gmp-password',cfg['greenbone_password'],'socket','--socketpath','/run/gvmd/gvmd.sock','--xml',xml],capture=True)
        node=ET.fromstring(raw)
        if not node.get('status','').startswith('2'):raise RuntimeError('Requête GMP refusée : '+node.get('status','?'))
        return node
    prov.wait('API Greenbone',lambda:gmp('<get_version/>'),7200)
    def ready():
        configs=gmp('<get_configs/>')
        return configs if configs.findall('config') else False
    configs=prov.wait('Feeds/configurations Greenbone',ready,7200)
    choices=configs.findall('config');config=next((x for x in choices if x.findtext('name')=='Full and fast'),choices[0])
    ports=gmp('<get_port_lists/>').findall('port_list')
    scanners=gmp('<get_scanners/>').findall('scanner')
    if not ports or not scanners:raise RuntimeError('Port list ou scanner Greenbone absent.')
    scanner=next((x for x in scanners if x.findtext('type')=='2'),scanners[0])
    tasks=[]
    saved.setdefault('gvm_targets',{});saved.setdefault('gvm_tasks',{})
    for ip in cfg['targets']:
        name='SOC '+ip
        if ip not in saved['gvm_targets']:
            r=gmp('<create_target><name>'+escape(name)+'</name><hosts>'+escape(ip)+'</hosts><port_list id="'+ports[0].get('id')+'"/></create_target>')
            saved['gvm_targets'][ip]=r.get('id');persist()
        if ip not in saved['gvm_tasks']:
            r=gmp('<create_task><name>'+escape(name)+'</name><target id="'+saved['gvm_targets'][ip]+'"/><config id="'+config.get('id')+'"/><scanner id="'+scanner.get('id')+'"/></create_task>')
            saved['gvm_tasks'][ip]=r.get('id');persist()
        tasks.append(saved['gvm_tasks'][ip])
    return {'gmp':'authentifié','configurations_feed':len(choices),'taches_creees':tasks,'scans_lances':False}

def transfer(cfg,saved):
    folder=ROOT/'transfert';fresh(folder);shutil.copy2(HERE/'transfert.py',folder/'transfert.py')
    ids=infra.run(infra.compose_cmd(ROOT/'stacks/wazuh')+['ps','-q','wazuh.manager'],capture=True).strip()
    if not ids:raise RuntimeError('Wazuh Manager introuvable pour le transfert.')
    container=json.loads(infra.run(['docker','inspect',ids],capture=True))[0]['Name'].lstrip('/')
    vals={'SHUFFLE_WEBHOOK_URL':'http://127.0.0.1:5001/api/v1/hooks/webhook_'+saved['hook'],'WAZUH_CONTAINER':container,'MIN_LEVEL':'7','SOC_MAX_PER_MINUTE':'6','SOC_TAIL_LINES':'0','SOC_QUEUE_DB':str(folder/'queue.sqlite3')}
    infra.write('/etc/wazuh-to-soc.env','\n'.join(k+'='+json.dumps(v) for k,v in vals.items())+'\n')
    infra.write('/etc/systemd/system/wazuh-to-soc.service','[Unit]\nDescription=Transfert Wazuh vers Shuffle\nAfter=docker.service\nRequires=docker.service\n[Service]\nEnvironmentFile=/etc/wazuh-to-soc.env\nExecStart=/usr/bin/python3 '+str(folder/'transfert.py')+'\nRestart=always\nRestartSec=10\n[Install]\nWantedBy=multi-user.target\n',0o644)
    infra.run(['systemctl','daemon-reload']);infra.run(['systemctl','enable','--now','wazuh-to-soc.service'])
    if infra.service_state('wazuh-to-soc.service')!='active':raise RuntimeError('Transfert non actif.')
    return {'service':'actif','niveau_minimum':7,'debit_maximum':6}

def wazuh_decoder_test():
    folder=ROOT/'stacks/wazuh'
    cid=infra.run(infra.compose_cmd(folder)+['ps','-q','wazuh.manager'],capture=True).strip()
    event={'event_type':'alert','src_ip':'192.0.2.10','dest_ip':'192.0.2.20','alert':{'signature':'SOC installation parser test'}}
    output=infra.run(['docker','exec','-i',cid,'/var/ossec/bin/wazuh-logtest'],data=json.dumps(event)+'\n',capture=True)
    if not re.search(r"id:\s*['\"]100230['\"]",output):raise RuntimeError('Règle Wazuh Suricata non confirmée par wazuh-logtest.')
    return {'regle':'100230','test':'décodage/corrélation local ; pas un événement réseau réel'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,help='Configuration JSON privée générée par --preparer')
    parser.add_argument('--preparer',action='store_true',help='Saisir et sauvegarder les paramètres sans installer')
    parser.add_argument('--reprendre',action='store_true',help='Reprendre les étapes incomplètes')
    args=parser.parse_args()
    if os.geteuid():parser.error('Lancer avec sudo bash deploy_soc.sh')
    os.umask(0o077)
    configpath=args.config or ROOT/'configuration-privee.json'
    if configpath.exists():cfg=json.loads(configpath.read_text())
    else:
        cfg=ask_config();save(configpath,cfg)
    if args.preparer:print('Configuration privée enregistrée : '+str(configpath));return
    existing=ROOT/'etat.json'
    state=json.loads(existing.read_text()) if existing.exists() else {'etapes':{},'initialisation':{}}
    fingerprint=hashlib.sha256(json.dumps(cfg,sort_keys=True).encode()).hexdigest()
    if state.get('configuration_sha256') not in (None,fingerprint):raise RuntimeError('Configuration modifiée depuis le début : reprise automatique refusée.')
    state['configuration_sha256']=fingerprint
    if existing.exists() and not args.reprendre:raise RuntimeError('Installation déjà commencée. Utiliser --reprendre, sans supprimer les données.')
    lockfile=Path('/run/soc-autonome.lock')
    with lockfile.open('w') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise RuntimeError('Une installation SOC est déjà en cours.')
        fresh(ROOT);infra.ROOT=ROOT;infra.LOG=ROOT/'installation-privee.log'
        def persist():save(existing,state)
        def step(name,fn):
            if state['etapes'].get(name,{}).get('etat')=='terminee':print('Déjà terminé : '+name,flush=True);return
            state['etapes'][name]={'etat':'en_cours'};persist();print('ÉTAPE : '+name,flush=True)
            try: result=fn();state['etapes'][name]={'etat':'terminee','resultat':result};persist()
            except Exception as e:
                state['etapes'][name]={'etat':'echec','erreur':type(e).__name__};persist();raise
        if not args.reprendre:
            class A: interface=cfg['interface']
            infra.preflight(infra.TOOLS,A())
        step('ubuntu-docker',lambda:infra.bootstrap() or {})
        infra.run(['apt-get','install','-y','python3-bcrypt'])
        if 'soc_network' not in infra.run(['docker','network','ls','--format','{{.Name}}'],capture=True).splitlines():infra.run(['docker','network','create','soc_network'])
        stacks=ROOT/'stacks';fresh(stacks)
        for name,fn in [('wazuh',wazuh_install),('thehive-cortex',hive_install),('misp',misp_install),('shuffle',shuffle_install),('greenbone',greenbone_install)]:
            step('infra-'+name,lambda n=name,f=fn:f(stacks/n,cfg))
        def native(name,fn):
            folder=stacks/name;fresh(folder);return fn(folder)
        step('suricata',lambda:native('suricata',lambda p:infra.install_suricata(p,cfg['ip'],cfg['interface'])))
        step('tenzir',lambda:native('tenzir',lambda p:infra.install_tenzir(p,cfg['ip'])))
        saved=state['initialisation']
        step('initialiser-cortex',lambda:prov.cortex(cfg,saved,persist))
        step('initialiser-thehive',lambda:prov.thehive(cfg,saved,persist))
        step('initialiser-misp',lambda:prov.misp(cfg,saved,persist))
        step('workflows-shuffle',lambda:prov.shuffle(cfg,saved,persist,HERE/'templates'))
        step('initialiser-greenbone',lambda:greenbone_setup(stacks/'greenbone',cfg,saved,persist))
        step('test-decodeur-wazuh',wazuh_decoder_test)
        step('test-integration',lambda:prov.integration_test(cfg,saved,persist))
        step('transfert-wazuh',lambda:transfer(cfg,saved))
        print('Déploiement et initialisations terminés. Contrôles de bout en bout et réception du mail encore à vérifier.')
        print('Rapport privé : '+str(existing))
        print('Agents Windows/Odoo : installation distincte sur les machines à superviser. Aucun confinement automatique.')

if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt) as e:
        print('ARRÊT : '+(str(e) if isinstance(e,RuntimeError) else type(e).__name__),file=sys.stderr)
        print('Aucun succès global déclaré. Consulter /opt/soc/autonome/etat.json ; données conservées.',file=sys.stderr)
        sys.exit(1)
