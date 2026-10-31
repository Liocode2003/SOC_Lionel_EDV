#!/usr/bin/env python3
"""Déploiement SOC de laboratoire. Audit par défaut. Python standard uniquement."""
import argparse, datetime, fcntl, getpass, hashlib, ipaddress, json, os
from pathlib import Path
import re, secrets, shlex, shutil, socket, ssl, subprocess, sys, tarfile, time
import urllib.request, urllib.error

ROOT = Path('/opt/soc/autonome')
HERE = Path(__file__).resolve().parent
TOOLS = ['wazuh', 'thehive-cortex', 'misp', 'shuffle', 'greenbone', 'suricata', 'tenzir']
URLS = {
 'wazuh':'https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html',
 'thehive-cortex':'https://docs.strangebee.com/resources/docker-demo/',
 'misp':'https://github.com/MISP/misp-docker',
 'shuffle':'https://github.com/Shuffle/Shuffle',
 'greenbone':'https://greenbone.github.io/docs/latest/22.4/container/',
 'suricata':'https://docs.suricata.io/en/latest/quickstart.html',
 'tenzir':'https://tenzir.com/docs/guides/installation/'}
STAMP = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
LOG = None

def say(msg):
    print(msg, flush=True)

def write(path, content, mode=0o600):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    # Ne jamais suivre un lien pour les fichiers administratifs produits ici.
    if path.is_symlink(): raise RuntimeError('Lien symbolique refusé : '+str(path))
    tmp = path.with_name(path.name+'.tmp-'+secrets.token_hex(4))
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    with os.fdopen(fd, 'w') as f: f.write(content)
    os.replace(tmp, path); path.chmod(mode)

def dump(path, obj): write(path, json.dumps(obj, ensure_ascii=False, indent=2)+'\n')

def run(args, cwd=None, capture=False, data=None, timeout=None, check=True, env=None):
    global LOG
    # Les sorties des éditeurs peuvent contenir des mots de passe : journal privé.
    result = subprocess.run([str(x) for x in args], cwd=cwd, input=data,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=env)
    if LOG:
        with LOG.open('a') as f:
            f.write('\n--- '+str(args[0])+' (code '+str(result.returncode)+') ---\n')
            f.write(result.stdout or ''); f.write(result.stderr or '')
    if check and result.returncode:
        raise RuntimeError('Commande échouée : '+str(args[0])+' ; code '+str(result.returncode)
                           + (' ; journal privé : '+str(LOG) if LOG else ''))
    return result.stdout if capture else result

def download(url, dest):
    # Certificats vérifiés, pas de curl | bash.
    with urllib.request.urlopen(url, timeout=90) as r:
        data = r.read(30*1024*1024+1)
    if len(data)>30*1024*1024: raise RuntimeError('Téléchargement trop volumineux')
    write(dest, data.decode())
    return hashlib.sha256(data).hexdigest()

def env_update(path, values):
    text = path.read_text() if path.exists() else ''
    for key,value in values.items():
        # Nos secrets sont hexadécimaux. Interdire les caractères interprétés par Compose.
        value = str(value)
        if any(c in value for c in '\n\r$'): raise RuntimeError('Valeur .env invalide : '+key)
        line = key+'='+value
        pattern = r'^\s*'+re.escape(key)+r'\s*=.*$'
        if re.search(pattern,text,re.M): text = re.sub(pattern,lambda _:line,text,flags=re.M)
        else: text += '\n'+line+'\n'
    write(path,text)

def compose_cmd(folder, file=None):
    return ['docker','compose','--project-directory',str(folder),'-f',str(file or folder/'compose.lock.json')]

def raw_config(folder, file):
    return json.loads(run(['docker','compose','--project-directory',str(folder),'-f',str(file),
                           'config','--format','json'],capture=True,cwd=folder))

def containers():
    if not shutil.which('docker'): return []
    ids=run(['docker','ps','-aq'],capture=True).split()
    if not ids: return []
    return json.loads(run(['docker','inspect',*ids],capture=True))

def identify(c):
    n=c.get('Name','').lower(); image=c.get('Config',{}).get('Image','').lower()
    s=n+' '+image
    if 'wazuh' in s:return 'wazuh'
    if any(x in s for x in ('thehive','cortex','strangebee')):return 'thehive-cortex'
    if 'misp' in s:return 'misp'
    if 'shuffle' in s:return 'shuffle'
    if 'greenbone' in s or 'openvas' in s or '/gvmd' in s:return 'greenbone'
    if 'tenzir' in s:return 'tenzir'
    if 'suricata' in s:return 'suricata'
    return None

def service_state(name):
    if not shutil.which('systemctl'):return 'indisponible'
    return run(['systemctl','is-active',name],capture=True,check=False).strip()

def probe(url):
    # Une réponse HTTP authentification ne prouve pas le bon fonctionnement de l'API.
    try:
        with urllib.request.urlopen(url,timeout=5) as r:return {'http':r.status,'tls':'vérifié'}
    except urllib.error.HTTPError as e:return {'http':e.code,'tls':'vérifié'}
    except urllib.error.URLError as e:
        if isinstance(e.reason,ssl.SSLCertVerificationError):
            return {'http':None,'tls':'certificat non approuvé ; non contourné'}
        return {'http':None,'erreur':type(e.reason).__name__}
    except Exception as e:return {'http':None,'erreur':type(e).__name__}

def audit(ip):
    cs=containers(); report={'date':STAMP,'type':'audit infrastructure, pas test de détection',
       'outils':{},'systeme':{},'limites':[
        'Un conteneur running ou une interface HTTP accessible ne prouve pas une intégration fonctionnelle.',
        'Aucun scan, mail, événement synthétique ni confinement déclenché.']}
    for tool in TOOLS:
        matches=[c for c in cs if identify(c)==tool]
        found=[]
        for c in matches:
            state=c.get('State',{});health=(state.get('Health') or {}).get('Status','sans healthcheck')
            found.append({'nom':c['Name'].lstrip('/'),'image':c['Config']['Image'],
                          'etat':state.get('Status'),'sante':health})
        native={}
        if tool in ('suricata','tenzir'):
            names=['suricata','soc-suricata'] if tool=='suricata' else ['tenzir','soc-tenzir-pipeline']
            native={n:service_state(n) for n in names}
        report['outils'][tool]={'conteneurs':found,'services':native}
        states=[x['etat']+'/'+x['sante'] for x in found]+[k+':'+v for k,v in native.items() if v=='active']
        say(tool+' : '+(', '.join(states) if states else 'non trouvé'))
    forwarding=service_state('wazuh-to-soc.service')
    say('Transfert Wazuh → Shuffle : '+forwarding)
    report['systeme']['transfert']=forwarding
    report['systeme']['espace_libre_Gio']=round(shutil.disk_usage('/').free/1024**3,1)
    report['systeme']['memoire_Mio']=int(re.search(r'MemTotal:\s+(\d+)',Path('/proc/meminfo').read_text()).group(1))//1024
    endpoints={'wazuh':f'https://{ip}:443','thehive':f'http://{ip}:9000',
      'cortex':f'http://{ip}:9001','misp':f'https://{ip}:8443','shuffle':f'http://{ip}:3001',
      'greenbone':f'http://{ip}:9392'}
    report['interfaces']={name:{'url':url,**probe(url)} for name,url in endpoints.items()}
    directory=ROOT/'rapports';dump(directory/('audit-'+STAMP+'.json'),report)
    say('Rapport : '+str(directory/('audit-'+STAMP+'.json')))
    return report

def backup():
    # Configurations seulement. Pas de copie à chaud présentée comme sauvegarde des bases.
    folder=ROOT/'sauvegardes'/STAMP; folder.mkdir(parents=True,mode=0o700)
    cs=containers(); paths=set()
    for c in cs:
        if not identify(c):continue
        labels=c.get('Config',{}).get('Labels') or {}
        for x in labels.get('com.docker.compose.project.config_files','').split(','):
            if x and Path(x).is_file(): paths.add(Path(x))
        wd=labels.get('com.docker.compose.project.working_dir')
        if wd and (Path(wd)/'.env').is_file():paths.add(Path(wd)/'.env')
    for p in ('/etc/wazuh-to-soc.env','/etc/systemd/system/wazuh-to-soc.service',
              '/opt/soc/wazuh-to-soc/wazuh_to_soc.py','/etc/suricata/suricata.yaml',
              '/etc/systemd/system/soc-tenzir-pipeline.service',str(ROOT/'etat.json')):
        if Path(p).is_file():paths.add(Path(p))
    # Manifeste inspect privé : peut inclure des identifiants dans Config.Env.
    dump(folder/'docker-inspect-prive.json',cs)
    with tarfile.open(folder/'configurations.tar.gz','w:gz') as tf:
        for p in sorted(paths):tf.add(p,arcname=str(p).lstrip('/'),recursive=False)
    (folder/'configurations.tar.gz').chmod(0o600)
    write(folder/'LIRE.txt','Sauvegarde des fichiers de configuration et inventaire Docker.\n'
          'Ne contient PAS les bases, volumes, pièces jointes ni les workflows du backend.\n'
          'Pour un retour complet : snapshot VM à froid ou sauvegardes cohérentes propres à chaque base.\n'
          'Fichiers privés : peuvent contenir des clés et mots de passe.\n')
    say('Configurations sauvegardées : '+str(folder))

def bootstrap():
    release=Path('/etc/os-release').read_text()
    if 'ID=ubuntu' not in release or 'VERSION_ID="24.04"' not in release:
        raise RuntimeError('Installation neuve prévue pour Ubuntu 24.04 uniquement')
    run(['apt-get','update'])
    run(['apt-get','install','-y','ca-certificates','curl','git','jq','openssl',
         'python3-yaml','software-properties-common','cron','iproute2'])
    if not shutil.which('docker'):
        # Ne pas supprimer une installation Docker existante ou ses paquets.
        Path('/etc/apt/keyrings').mkdir(exist_ok=True)
        download('https://download.docker.com/linux/ubuntu/gpg',Path('/etc/apt/keyrings/docker.asc'))
        Path('/etc/apt/keyrings/docker.asc').chmod(0o644)
        arch=run(['dpkg','--print-architecture'],capture=True).strip()
        write('/etc/apt/sources.list.d/docker.sources',
          'Types: deb\nURIs: https://download.docker.com/linux/ubuntu\nSuites: noble\n'
          'Components: stable\nArchitectures: '+arch+'\nSigned-By: /etc/apt/keyrings/docker.asc\n',0o644)
        run(['apt-get','update'])
        run(['apt-get','install','-y','docker-ce','docker-ce-cli','containerd.io','docker-buildx-plugin','docker-compose-plugin'])
        run(['systemctl','enable','--now','docker'])
    run(['docker','info']);run(['docker','compose','version'])
    # Préserve une valeur existante plus élevée.
    old=int(run(['sysctl','-n','vm.max_map_count'],capture=True).strip())
    if old<262144:
        write('/etc/sysctl.d/90-soc.conf','vm.max_map_count=262144\n',0o644)
        run(['sysctl','-w','vm.max_map_count=262144'])

def clone(url, target, ref=None):
    if not target.exists():
        cmd=['git','clone','--depth','1']
        if ref and not re.fullmatch(r'[0-9a-f]{40}',ref):cmd+=['--branch',ref]
        run(cmd+[url,str(target)])
        if ref and re.fullmatch(r'[0-9a-f]{40}',ref):
            run(['git','fetch','--depth','1','origin',ref],cwd=target)
            run(['git','checkout','--detach',ref],cwd=target)
    elif not (target/'.git').is_dir():raise RuntimeError('Répertoire non géré : '+str(target))
    return run(['git','rev-parse','HEAD'],cwd=target,capture=True).strip()

def pin_and_start(folder, cfg, services=None):
    # Réseau commun utilisé par les actions Shuffle et les APIs internes.
    if folder.name!='greenbone':
        cfg.setdefault('networks',{})['soc_network']={'external':True,'name':'soc_network'}
        for service in cfg['services'].values():
            networks=service.setdefault('networks',{})
            if isinstance(networks,list):networks={x:{} for x in networks};service['networks']=networks
            networks.setdefault('soc_network',{})
    # Résoudre les tags une fois en digests et conserver un manifeste verrouillé.
    for name,s in cfg['services'].items():
        s.pop('build',None)
        if s.get('image'):
            run(['docker','pull',s['image']])
            obj=json.loads(run(['docker','image','inspect',s['image']],capture=True))[0]
            digests=obj.get('RepoDigests') or []
            if not digests:raise RuntimeError('Digest image absent : '+name)
            s['image']=digests[0]
        s.setdefault('logging',{'driver':'json-file','options':{'max-size':'10m','max-file':'3'}})
    cfg['name']='soc-'+folder.name
    dump(folder/'compose.lock.json',cfg)
    cmd=compose_cmd(folder)
    run(cmd+['config','--quiet'],cwd=folder)
    run(cmd+['up','-d','--pull','never']+(services or []),cwd=folder)
    # Vérification réelle de l'état ; les services init terminés avec code 0 sont permis.
    ids=run(cmd+['ps','-aq'],capture=True,cwd=folder).split()
    deadline=time.monotonic()+int(os.environ.get('SOC_READY_TIMEOUT','7200'))
    while ids:
        items=json.loads(run(['docker','inspect',*ids],capture=True));ready=True
        for c in items:
            state=c['State'];health=(state.get('Health') or {}).get('Status')
            restart=c['HostConfig'].get('RestartPolicy',{}).get('Name','no')
            if state['Status']=='exited' and state['ExitCode']==0 and restart in ('no',''):continue
            if state['Status']!='running' or health in ('starting','unhealthy'):ready=False
            if state.get('OOMKilled'):raise RuntimeError('Manque mémoire : '+c['Name'])
        if ready:return
        if time.monotonic()>deadline:raise RuntimeError('Disponibilité non confirmée dans les 10 minutes : '+folder.name)
        say('Initialisation en cours : '+folder.name+'…');time.sleep(10)
    raise RuntimeError('Aucun conteneur créé : '+folder.name)

def install_wazuh(folder, ip):
    repo=folder/'source';commit=clone('https://github.com/wazuh/wazuh-docker.git',repo,'v4.14.9')
    wd=repo/'single-node'
    run(['docker','compose','-f','generate-indexer-certs.yml','run','--rm','generator'],cwd=wd)
    # Collecte réseau vers Wazuh, sans changer les événements EVE et leurs IP.
    logs=Path('/var/log/soc-tenzir');logs.mkdir(parents=True,exist_ok=True)
    conf=wd/'config/wazuh_cluster/wazuh_manager.conf'
    text=conf.read_text()
    localfile='<localfile><log_format>json</log_format><location>/var/log/soc-tenzir/eve.json</location></localfile>'
    if '/var/log/soc-tenzir/eve.json' not in text:
        if '</ossec_config>' not in text:raise RuntimeError('Structure ossec_config inattendue')
        write(conf,text.replace('</ossec_config>',localfile+'\n</ossec_config>',1),0o644)
    rules=folder/'soc_suricata.xml'
    write(rules,'<group name="soc_suricata,">\n'
      '<rule id="100230" level="10"><decoded_as>json</decoded_as>'
      '<field name="event_type">^alert$</field><field name="alert.signature">.+</field>'
      '<description>Suricata : $(alert.signature)</description></rule>\n</group>\n',0o644)
    cfg=raw_config(wd,wd/'docker-compose.yml')
    manager=cfg['services']['wazuh.manager']
    manager.setdefault('volumes',[]).extend([
      {'type':'bind','source':str(logs),'target':'/var/log/soc-tenzir','read_only':True},
      {'type':'bind','source':str(rules),'target':'/var/ossec/etc/rules/soc_suricata.xml','read_only':True}])
    # Chemins absolus du manifeste résolu ; les volumes restent dans le dépôt.
    pin_and_start(folder,cfg)
    return {'commit':commit,'configuration_requise':[
       'Remplacer les identifiants de démonstration Wazuh selon la procédure officielle.',
       'Enrôler les agents Windows ; configurer les journaux Odoo et règles souhaitées.']}

def install_suricata(folder,ip,iface):
    import yaml
    if not iface or not Path('/sys/class/net',iface).exists():
        raise RuntimeError('Interface réseau réelle requise : --interface ens33 (exemple)')
    run(['add-apt-repository','-y','ppa:oisf/suricata-stable']);run(['apt-get','update'])
    run(['apt-get','install','-y','suricata','suricata-update'])
    run(['systemctl','stop','suricata'])
    # Conserver le fichier d'origine et utiliser un fichier propre au laboratoire.
    original=Path('/etc/suricata/suricata.yaml');shutil.copy2(original,folder/'suricata.original.yaml')
    cfg=yaml.safe_load(original.read_text());cfg['af-packet']=[{'interface':iface,'cluster-id':99,
       'cluster-type':'cluster_flow','defrag':True,'use-mmap':True,'tpacket-v3':True}]
    for entry in cfg.get('outputs',[]):
        if 'eve-log' in entry:
            entry['eve-log'].update({'enabled':True,'filetype':'regular','filename':'eve.json'})
    write(folder/'suricata.yaml',yaml.safe_dump(cfg))
    run(['suricata-update'])
    run(['suricata','-T','-c',str(folder/'suricata.yaml')])
    write('/etc/systemd/system/soc-suricata.service',
      '[Unit]\nDescription=Suricata SOC IDS (sans blocage)\nAfter=network-online.target\n'
      '[Service]\nType=simple\nExecStart=/usr/bin/suricata -c '+str(folder/'suricata.yaml')+' --af-packet='+iface+'\n'
      'Restart=on-failure\nRestartSec=5\n[Install]\nWantedBy=multi-user.target\n',0o644)
    run(['systemctl','disable','suricata']);run(['systemctl','daemon-reload'])
    run(['systemctl','enable','--now','soc-suricata'])
    if service_state('soc-suricata')!='active':raise RuntimeError('Suricata non actif')
    return {'interface':iface,'mode':'IDS, aucune règle de blocage',
       'configuration_requise':['Configurer le miroir réseau/TAP du lab ; sans visibilité réseau, pas de détection.',
        'Vérifier HOME_NET et règles ; ne pas conclure à une couverture XSS Odoo sans test réel.']}

def install_tenzir(folder,ip):
    image='ghcr.io/tenzir/tenzir:latest';run(['docker','pull',image])
    obj=json.loads(run(['docker','image','inspect',image],capture=True))[0];image=obj['RepoDigests'][0]
    # Test de parsing réel avant de déclarer le binaire disponible.
    pipeline='from_stdin { read_suricata }\nto_stdout { write_ndjson }'
    event={'timestamp':'2026-01-01T00:00:00Z','event_type':'alert','src_ip':'192.0.2.1',
      'dest_ip':'192.0.2.2','proto':'TCP','alert':{'signature':'SOC parser test','signature_id':1000001,'severity':3}}
    result=run(['docker','run','--rm','-i',image,pipeline],data=json.dumps(event)+'\n',capture=True)
    rows=[json.loads(x) for x in result.splitlines() if x.strip()]
    if not rows or rows[0].get('event_type')!='alert':raise RuntimeError('Parsing Tenzir non confirmé')
    dump(folder/'image.json',{'image':image})
    # Le pipeline lit uniquement les nouvelles lignes. Une interruption de tail peut perdre des événements.
    output=Path('/var/log/soc-tenzir');output.mkdir(parents=True,exist_ok=True)
    command='tail -n 0 -F /var/log/suricata/eve.json | '+shlex.join(
      ['docker','run','--rm','--name','soc-tenzir-stream','-i',image,pipeline])+' >> /var/log/soc-tenzir/eve.json'
    write(folder/'pipeline.sh','#!/bin/bash\nset -euo pipefail\n'+command+'\n',0o750)
    write('/etc/systemd/system/soc-tenzir-pipeline.service',
      '[Unit]\nDescription=Suricata vers Tenzir, sortie NDJSON\nAfter=docker.service soc-suricata.service\nRequires=docker.service\n'
      '[Service]\nExecStart=/bin/bash '+str(folder/'pipeline.sh')+'\n'
      'ExecStopPost=-/usr/bin/docker rm -f soc-tenzir-stream\nRestart=always\nRestartSec=10\n'
      '[Install]\nWantedBy=multi-user.target\n',0o644)
    write('/etc/logrotate.d/soc-tenzir','/var/log/soc-tenzir/eve.json {\n daily\n rotate 7\n compress\n missingok\n notifempty\n copytruncate\n}\n',0o644)
    run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','soc-tenzir-pipeline'])
    if service_state('soc-tenzir-pipeline')!='active':raise RuntimeError('Pipeline Tenzir non actif')
    return {'image':image,'test_parseur':'réussi',
       'configuration_requise':['Le Wazuh installé par ce paquet collecte /var/log/soc-tenzir/eve.json ; sinon configurer ce montage et localfile JSON.',
       'Vérifier une alerte réseau de bout en bout. Ce pipeline seul ne prouve pas la réception Wazuh.'],
       'limites':['Pipeline de laboratoire sans reprise persistante pendant les interruptions.',
                  'copytruncate peut perdre quelques lignes lors de la rotation ; dimensionner avant production.']}

def preflight(selected,args):
    current=containers()
    known={identify(c) for c in current}
    collisions=[t for t in selected if t in known]
    if collisions:
        raise RuntimeError('Installation existante détectée : '+', '.join(collisions)+'. '
          'Aucun remplacement. Utiliser --audit sur cette VM ; installer sur une nouvelle VM.')
    for t,units in [('suricata',['suricata','soc-suricata']),('tenzir',['tenzir','soc-tenzir-pipeline'])]:
        if t in selected and (shutil.which(t) or any(service_state(u)=='active' for u in units)):
            raise RuntimeError('Service existant détecté : '+t+' ; installation neuve refusée')
    # Garde de capacité volontaire pour ce regroupement de lab ; ce n'est pas un benchmark éditeur.
    mem=int(re.search(r'MemTotal:\s+(\d+)',Path('/proc/meminfo').read_text()).group(1))/1024**2
    disk=shutil.disk_usage('/').free/1024**3
    if len(selected)>3 and (mem<30 or disk<150):
        raise RuntimeError(f'Lab complet : garde de capacité 32 Go RAM / 150 Gio libres ; disponibles {mem:.1f} Go / {disk:.1f} Gio. '
         'Déployer sur une VM plus grande ou répartir les composants avec --outils.')
    if 'suricata' in selected and (not args.interface or not Path('/sys/class/net',args.interface).exists()):
        raise RuntimeError('Préciser --interface avec une interface existante (commande ip -br link).')
    ports={'wazuh':[443,1514,1515,55000],'thehive-cortex':[9000,9001],
           'misp':[8080,8443],'shuffle':[3001,3443,5001],'greenbone':[9392]}
    for tool in selected:
        for port in ports.get(tool,[]):
            with socket.socket() as sock:
                try:sock.bind(('0.0.0.0',port))
                except OSError:raise RuntimeError('Port déjà utilisé : '+str(port)+' ('+tool+')')
