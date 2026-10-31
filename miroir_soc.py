#!/usr/bin/env python3
"""Miroir privé du laboratoire SOC : export à froid et restauration isolée."""
import argparse
import copy
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timezone
from urllib.parse import quote

NAMES = {'shuffle-orborus', 'shuffle-frontend', 'shuffle-backend', 'shuffle-opensearch',
         'shuffle-database', 'wazuh-wazuh-dashboard-1', 'wazuh-wazuh-manager-1',
         'wazuh-wazuh-indexer-1', 'openvas', 'misp', 'misp-db', 'misp-redis',
         'thehive', 'cortex', 'es-cortex', 'tenzir-node'}
UNITS = ('wazuh-to-soc.service', 'suricata.service', 'soc-suricata.service',
         'soc-tenzir-pipeline.service', 'tenzir-pipeline.service')
HOST_PATHS = ('/opt/soc', '/opt/thp', '/opt/shuffle', '/opt/wazuh', '/opt/Cortex-Analyzers',
              '/etc/suricata', '/var/lib/suricata', '/etc/wazuh-to-soc.env',
              '/etc/systemd/system/wazuh-to-soc.service',
              '/etc/systemd/system/soc-suricata.service',
              '/etc/systemd/system/soc-tenzir-pipeline.service',
              '/etc/systemd/system/tenzir-pipeline.service')
class Error(Exception): pass

def run(args, timeout=None):
    p = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if p.returncode:
        # Les erreurs Docker peuvent contenir des valeurs privées : journal sur disque uniquement.
        raise Error('Commande échouée : ' + ' '.join(args[:2]) + ' (code %s)' % p.returncode)
    return p.stdout.strip()

def dj(*args): return json.loads(run(['docker', *args]))
def write(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(8*1024*1024), b''): h.update(b)
    return h.hexdigest()
def root():
    if os.geteuid(): raise Error('Lancer avec sudo sur Ubuntu.')
    os.umask(0o077)
    if not Path('/var/run/docker.sock').exists(): raise Error('Docker local est requis.')

def unit_state(name):
    s = run(['systemctl','show',name,'--property=LoadState,ActiveState,UnitFileState'])
    return dict(x.split('=',1) for x in s.splitlines() if '=' in x)

def collapse(paths):
    selected = []
    for p in sorted(set(map(str, paths)), key=lambda x: (len(Path(x).parts), x)):
        if not any(Path(p) == Path(q) or Path(q) in Path(p).parents for q in selected): selected.append(p)
    return selected

def allowed_bind(path):
    p = Path(path)
    return p.is_absolute() and '..' not in p.parts and (
        any(Path(base) == p or Path(base) in p.parents for base in ('/opt', '/etc/suricata', '/var/log/suricata', '/var/lib/suricata'))
        and str(p) not in ('/opt',))

def archive(output, base, members):
    run(['tar','--acls','--xattrs','--numeric-owner','--sparse','-cpf',str(output),'-C',str(base),'--',*members])

def verify_tar(path):
    # Ces archives sont des sauvegardes administrateur de confiance, pas des imports publics.
    # Refuser traversées et liens sortant de la racine, ainsi que les périphériques.
    links = set()
    with tarfile.open(path) as tf:
        for m in tf:
            p = PurePosixPath(m.name)
            if p.is_absolute() or '..' in p.parts or m.isdev() or m.isfifo():
                raise Error('Chemin/type non autorisé dans une archive.')
            if any(str(parent) in links for parent in p.parents):
                raise Error('Archive comportant une écriture à travers un lien symbolique.')
            if m.issym():
                links.add(str(p))
                # Liens absolus autorisés : présents dans les installations système.
                # Aucune entrée descendante ne doit les suivre (vérifiée ci-dessous aussi).
            if m.islnk() and (PurePosixPath(m.linkname).is_absolute() or '..' in PurePosixPath(m.linkname).parts):
                raise Error('Lien physique non autorisé.')
    with tarfile.open(path) as tf:
        for m in tf:
            if any(str(parent) in links for parent in PurePosixPath(m.name).parents):
                raise Error('Archive écrivant à travers un lien.')

def export(args):
    root()
    out = args.dossier.resolve()
    if out.exists(): raise Error('Destination déjà présente ; choisir un nouveau dossier.')
    if any(Path(p) == out or Path(p) in out.parents for p in HOST_PATHS):
        raise Error('Placer la sauvegarde hors des répertoires SOC, par exemple /root.')
    allc = dj('inspect', *run(['docker','ps','-aq']).split()) if run(['docker','ps','-aq']) else []
    selected = [c for c in allc if c['Name'].lstrip('/') in NAMES]
    missing = sorted(NAMES - {c['Name'].lstrip('/') for c in selected})
    if missing: raise Error('Conteneurs attendus absents : ' + ', '.join(missing))
    other_running = [c for c in allc if c not in selected and c['State']['Running']]
    if other_running:
        raise Error('D’autres conteneurs sont actifs (workers compris). Attendre la fin des exécutions ou les arrêter avant export.')
    volumes, networks, binds = {}, {}, []
    for c in selected:
        hc = c['HostConfig']
        if hc.get('AutoRemove'): raise Error('AutoRemove non pris en charge : '+c['Name'])
        if hc.get('NetworkMode','').startswith('container:') or hc.get('VolumesFrom'):
            raise Error('Partage de namespace/VolumesFrom non pris en charge.')
        for m in c['Mounts']:
            if m['Type']=='volume':
                v = dj('volume','inspect',m['Name'])[0]
                if v['Driver']!='local' or v.get('Options'): raise Error('Volume distant/spécial non pris en charge.')
                volumes[m['Name']] = v
            elif m['Type']=='bind':
                if m['Source']=='/var/run/docker.sock': continue
                if not allowed_bind(m['Source']): raise Error('Montage hors périmètre : '+m['Source'])
                binds.append(m['Source'])
            elif m['Type']!='tmpfs': raise Error('Type de montage non pris en charge.')
        for name in c['NetworkSettings']['Networks']:
            if name in ('bridge','host','none'): raise Error('Réseau natif non pris en charge pour ce miroir.')
            n=dj('network','inspect',name)[0]
            if n['Driver']!='bridge' or n.get('Scope')!='local': raise Error('Réseau non local non pris en charge.')
            networks[name]=n
    units = {u: unit_state(u) for u in UNITS}
    paths = collapse([p for p in HOST_PATHS if Path(p).exists()] + binds)
    for p in paths:
        if not Path(p).exists(): raise Error('Montage absent : '+p)
        if Path(p).is_symlink(): raise Error('Racine de montage symbolique non prise en charge : '+p)
    if not args.arret_confirme: raise Error('Relancer avec --arret-confirme pour autoriser cet arrêt temporaire.')
    out.mkdir(mode=0o700, parents=True)
    (out/'volumes').mkdir()
    print('Export privé :',out,flush=True)
    print('Les services SOC seront arrêtés pendant la copie. Prévoir plusieurs dizaines de Go et du temps.',flush=True)
    stopped_units, stopped = [], []
    packages={}
    for package in ('suricata','suricata-update','python3-requests','python3-yaml','python3-pip'):
        try: packages[package]=run(['dpkg-query','-W','-f=${Version}',package])
        except Error: pass
    manifest={'paquets_hote':packages,'schema':1,'date':datetime.now(timezone.utc).isoformat(),'architecture':platform.machine(),
              'docker_version':run(['docker','version','--format','{{.Server.Version}}']),
              'conteneurs':selected,'reseaux':networks,'volumes':{},'services':units,'host_paths':paths,
              'images':{},'fichiers':{},'etat':'incomplet'}
    write(out/'manifest.json',manifest)
    try:
        for u,s in units.items():
            if s['ActiveState']=='active':
                stopped_units.append(u)
                run(['systemctl','stop',u],timeout=120)
        # Orborus et backend en premier : empêcher le lancement de nouveaux workers.
        ordered=sorted(selected,key=lambda c: (0 if c['Name'].lstrip('/') in ('shuffle-orborus','shuffle-backend') else 1))
        for c in ordered:
            if c['State']['Running']:
                stopped.append(c['Name'].lstrip('/'))
                run(['docker','stop','--time','120',c['Id']],timeout=150)
            state=dj('inspect',c['Id'])[0]['State']
            if state['Running'] or state.get('OOMKilled') or (c['State']['Running'] and state.get('ExitCode')==137):
                raise Error('Arrêt non propre détecté : '+c['Name']+'. Export annulé.')
        # Recontrôler : aucun worker ne doit avoir été créé entre-temps.
        running=run(['docker','ps','-q'])
        if running: raise Error('Un conteneur est encore actif ; export annulé pour cohérence.')
        print('Services arrêtés ; copie des images et des données…',flush=True)
        stamp=out.name.lower()
        stamp=re.sub('[^a-z0-9]','',stamp)[-25:] or 'snapshot'
        tags=[]
        for i,c in enumerate(selected):
            tag='soc-miroir/'+stamp+':c'+str(i)
            run(['docker','commit',c['Id'],tag])
            manifest['images'][c['Id']]=tag
            tags.append(tag)
        # Inclure aussi les images d’analyseurs et de workers déjà téléchargées.
        extras=run(['docker','image','ls','--format','{{.Repository}}:{{.Tag}}']).splitlines()
        extras=[x for x in extras if x!='<none>:<none>' and not x.startswith('soc-miroir/')]
        run(['docker','image','save','-o',str(out/'images.tar'),*tags,*extras])
        archive(out/'hote.tar','/',[p.lstrip('/') for p in paths])
        for i,(name,v) in enumerate(volumes.items()):
            filename='volumes/v%03d.tar'%i
            archive(out/filename,v['Mountpoint'],['.'])
            manifest['volumes'][name]={'archive':filename,'labels':v.get('Labels') or {}}
        verify_tar(out/'hote.tar')
        for v in manifest['volumes'].values(): verify_tar(out/v['archive'])
        for p in sorted(out.rglob('*.tar')):
            manifest['fichiers'][str(p.relative_to(out))]=sha(p)
        manifest['etat']='export_termine'
        write(out/'manifest.json',manifest)
        print('Copie terminée. Redémarrage de la source…',flush=True)
    finally:
        errors=[]
        priority=['es-cortex','misp-db','misp-redis','shuffle-database','shuffle-opensearch','wazuh-wazuh-indexer-1','thehive','cortex','misp','wazuh-wazuh-manager-1','wazuh-wazuh-dashboard-1','shuffle-backend','shuffle-frontend','tenzir-node','openvas','shuffle-orborus']
        for name in sorted(stopped,key=lambda x: priority.index(x) if x in priority else 0):
            try: run(['docker','start',name])
            except Error: errors.append(name)
        for u in stopped_units:
            try: run(['systemctl','start',u],timeout=120)
            except Error: errors.append(u)
        if errors:
            print('REDÉMARRAGE À VÉRIFIER : '+', '.join(errors),file=sys.stderr)
            raise Error('Certains services de la source n’ont pas pu être relancés.')
    print('Export terminé : '+str(out),flush=True)
    print('Ne pas publier ce dossier : il contient les comptes, certificats, clés et données du SOC.')
    print('Les images soc-miroir créées restent en cache sur la source ; aucune suppression automatique.')

class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(120)
        self.sock.connect('/var/run/docker.sock')

def api(path,payload):
    conn=UnixConnection('localhost')
    try:
        version=run(['docker','version','--format','{{.Server.APIVersion}}'])
        body=json.dumps(payload).encode()
        conn.request('POST','/v'+version+path,body,{'Content-Type':'application/json'})
        response=conn.getresponse();raw=response.read()
        if response.status>=300: raise Error('API Docker : HTTP '+str(response.status)+' pour '+path.split('?')[0])
        return json.loads(raw or '{}')
    finally: conn.close()

def payload(c,image):
    cfg=copy.deepcopy(c['Config']);hc=copy.deepcopy(c['HostConfig'])
    cfg['Image']=image
    # Aucun lancement automatique, en particulier Orborus, le transfert et OpenVAS.
    hc['RestartPolicy']={'Name':'no','MaximumRetryCount':0}
    hc.pop('ContainerIDFile',None)
    hc.pop('ConsoleSize',None)
    hc.pop('Links',None)
    hc['NetworkMode']=next(iter(c['NetworkSettings']['Networks']))
    mounts=[]
    for m in c['Mounts']:
        if m['Type']=='tmpfs': continue
        source=m.get('Name') if m['Type']=='volume' else m['Source']
        item={'Type':m['Type'],'Source':source,'Target':m['Destination'],'ReadOnly':not m['RW']}
        if m['Type']=='volume': item['VolumeOptions']={'NoCopy':True}
        elif m.get('Propagation'): item['BindOptions']={'Propagation':m['Propagation']}
        mounts.append(item)
    hc['Binds']=None;hc['Mounts']=mounts
    cfg['HostConfig']=hc
    eps={}
    for name,n in c['NetworkSettings']['Networks'].items():
        item={}
        ipam=copy.deepcopy(n.get('IPAMConfig') or {})
        if n.get('IPAddress'): ipam['IPv4Address']=n['IPAddress']
        if n.get('GlobalIPv6Address'): ipam['IPv6Address']=n['GlobalIPv6Address']
        if ipam: item['IPAMConfig']=ipam
        aliases=[a for a in (n.get('Aliases') or []) if a not in (c['Id'],c['Id'][:12])]
        if aliases: item['Aliases']=aliases
        eps[name]=item
    cfg['NetworkingConfig']={'EndpointsConfig':eps}
    return cfg

def check_bundle(folder):
    m=json.loads((folder/'manifest.json').read_text())
    if m.get('schema')!=1 or m.get('etat')!='export_termine': raise Error('Export incomplet/incompatible.')
    if m['architecture']!=platform.machine(): raise Error('Architecture différente de la source.')
    required={'images.tar','hote.tar',*[v['archive'] for v in m['volumes'].values()]}
    if not required.issubset(m['fichiers']): raise Error('Empreintes manquantes dans le manifeste.')
    for name,h in m['fichiers'].items():
        p=PurePosixPath(name)
        if p.is_absolute() or '..' in p.parts: raise Error('Nom d’archive invalide.')
        if sha(folder/name)!=h: raise Error('Empreinte invalide : '+name)
    for name in ['hote.tar',*[v['archive'] for v in m['volumes'].values()]]: verify_tar(folder/name)
    roots=[PurePosixPath(p.lstrip('/')) for p in m['host_paths']]
    with tarfile.open(folder/'hote.tar') as tf:
        for member in tf:
            path=PurePosixPath(member.name)
            if not any(path==r or r in path.parents for r in roots):
                raise Error('Fichier hors du périmètre déclaré de la sauvegarde.')
    return m

def restore(args):
    root()
    if not args.vm_isolee: raise Error('Utiliser --vm-isolee uniquement sur une VM neuve sans accès au réseau du SOC source.')
    folder=args.dossier.resolve();m=check_bundle(folder)
    if run(['docker','ps','-aq']): raise Error('Des conteneurs existent déjà. Restauration réservée à une VM neuve.')
    if run(['docker','volume','ls','-q']): raise Error('Des volumes existent déjà sur la destination.')
    for p in m['host_paths']:
        if Path(p).exists() or Path(p).is_symlink(): raise Error('Chemin existant : '+p+' ; aucun écrasement.')
        for parent in Path(p).parents:
            if parent.is_symlink(): raise Error('Parent symbolique refusé : '+str(parent))
    for name in m['reseaux']:
        names=run(['docker','network','ls','--format','{{.Name}}']).splitlines()
        if name in names: raise Error('Réseau existant : '+name)
    for package in m.get('paquets_hote',{}):
        try: run(['dpkg-query','-W','-f=${Version}',package])
        except Error: raise Error('Paquet hôte manquant : '+package+'. Lancer installer_soc.sh sur la destination.')
    print('Vérifications terminées. Chargement des images privées…',flush=True)
    run(['docker','image','load','-i',str(folder/'images.tar')])
    # Les restaurations partielles restent sur disque en cas d’échec. Aucune purge automatique.
    for name,n in m['reseaux'].items():
        data={k:n[k] for k in ('Driver','Internal','Attachable','EnableIPv6','IPAM','Options','Labels') if k in n}
        data['Name']=name;api('/networks/create',data)
    for name,v in m['volumes'].items():
        api('/volumes/create',{'Name':name,'Driver':'local','Labels':v['labels']})
        dest=dj('volume','inspect',name)[0]['Mountpoint']
        run(['tar','--acls','--xattrs','--numeric-owner','-xpf',str(folder/v['archive']),'-C',dest])
    run(['tar','--acls','--xattrs','--numeric-owner','-xpf',str(folder/'hote.tar'),'-C','/'])
    for c in m['conteneurs']:
        name=c['Name'].lstrip('/')
        api('/containers/create?name='+quote(name,safe=''),payload(c,m['images'][c['Id']]))
    run(['systemctl','daemon-reload'])
    for u,s in m['services'].items():
        if s['LoadState']=='loaded': run(['systemctl','disable',u])
    print('Restauration des fichiers et conteneurs terminée. Tous les conteneurs restent arrêtés.')
    print('Transfert, scans et notifications non activés. Les politiques Docker de redémarrage sont désactivées.')
    print('Lire VALIDATION.md pour vérifier la copie et traiter les adresses IP avant activation.')
    write(folder/'restauration.json',{'date':datetime.now(timezone.utc).isoformat(),'etat':'restaure_non_demarre'})

def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='action',required=True)
    e=sub.add_parser('exporter');e.add_argument('--dossier',type=Path,required=True)
    e.add_argument('--arret-confirme',action='store_true')
    r=sub.add_parser('restaurer');r.add_argument('--dossier',type=Path,required=True)
    r.add_argument('--vm-isolee',action='store_true')
    a=p.parse_args()
    if os.geteuid(): raise Error('Lancer avec sudo.')
    with open('/run/soc-miroir.lock','w') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise Error('Une autre opération miroir est en cours.')
        if a.action=='exporter': export(a)
        else: restore(a)
if __name__=='__main__':
    try: main()
    except (Error,OSError,ValueError,subprocess.TimeoutExpired,KeyboardInterrupt) as e:
        print('ARRÊT : '+(str(e) if isinstance(e,Error) else type(e).__name__),file=sys.stderr)
        sys.exit(1)
