#!/usr/bin/env python3
"""Transfert Wazuh avec file SQLite persistante et debit borne."""
import os,sys,json,time,hashlib,sqlite3,threading,subprocess,urllib.request,urllib.error
from urllib.parse import urlsplit
from datetime import datetime,timezone
URL=os.environ.get('SHUFFLE_WEBHOOK_URL','').strip()
MIN_LEVEL=int(os.environ.get('MIN_LEVEL','7'))
DB=os.environ.get('SOC_QUEUE_DB','/opt/soc/wazuh-to-soc/queue.sqlite3')
RATE=max(1,min(30,int(os.environ.get('SOC_MAX_PER_MINUTE','6'))))
CONTAINER=os.environ.get('WAZUH_CONTAINER','wazuh-wazuh-manager-1')
ALERT_FILE=os.environ.get('WAZUH_ALERT_FILE','/var/ossec/logs/alerts/alerts.json')

def wazuh_to_exec(a):
    r=a.get('rule') or {};g=a.get('agent') or {}
    return dict(title=r.get('description','Wazuh alert'),level=int(r.get('level',0)),agent=g.get('name','unknown'),
                rule_id=str(r.get('id','unknown')),mitre=r.get('mitre',{}),timestamp=a.get('timestamp',''),full_alert=a)

def internal_noise(a):
    d=a.get('data') or {};al=d.get('alert') or {};h=d.get('http') or {}
    host=urlsplit(URL).hostname
    # Filtre cible sur l'anomalie Suricata observee, pas sur toutes les alertes du serveur SOC.
    return (str(al.get('signature_id'))=='2221036'
            and host in (d.get('src_ip'),d.get('dest_ip'),h.get('hostname'))
            and str(h.get('url','')).split('?')[0] in ('/api/v1/streams/results','/api/v1/streams')
            and str(d.get('src_port') or h.get('http_port')) in ('3001','5001'))

def post_json(url,payload,headers=None):
    req=urllib.request.Request(url,data=json.dumps(payload).encode(),headers={'Content-Type':'application/json',**(headers or {})},method='POST')
    try:
        with urllib.request.urlopen(req,timeout=20) as r: return r.status,''
    except urllib.error.HTTPError as e: return e.code,'HTTPError'
    except Exception as e: return 0,type(e).__name__

def connect():
    c=sqlite3.connect(DB,timeout=30)
    c.execute('PRAGMA journal_mode=WAL')
    c.execute('CREATE TABLE IF NOT EXISTS queue (id TEXT PRIMARY KEY,payload TEXT,status TEXT DEFAULT "pending",attempts INTEGER DEFAULT 0,next_at REAL DEFAULT 0,created REAL)')
    c.commit();return c

def enqueue(c,a):
    p=wazuh_to_exec(a)
    if p['level']<MIN_LEVEL or internal_noise(a): return False
    manager=str((a.get('manager') or {}).get('name','wazuh'))
    sid=a.get('id') or hashlib.sha256(json.dumps(a,sort_keys=True).encode()).hexdigest()
    key=hashlib.sha256((manager+':'+str(sid)).encode()).hexdigest()
    changed=c.execute('INSERT OR IGNORE INTO queue(id,payload,created) VALUES(?,?,?)',(key,json.dumps(p),time.time())).rowcount
    c.commit();return bool(changed)

def drain():
    c=connect()
    while True:
        row=c.execute('SELECT id,payload,attempts FROM queue WHERE status="pending" AND next_at<=? ORDER BY created LIMIT 1',(time.time(),)).fetchone()
        if not row: time.sleep(1);continue
        key,payload,attempts=row
        code,error=post_json(URL,json.loads(payload))
        if 200<=code<300:
            c.execute('UPDATE queue SET status="sent",payload="",next_at=0 WHERE id=?',(key,))
            print('[Shuffle] accepte HTTP='+str(code),flush=True)
        else:
            delay=min(900,10*2**min(attempts,7))
            c.execute('UPDATE queue SET attempts=attempts+1,next_at=? WHERE id=?',(time.time()+delay,key))
            print('[Shuffle] nouvel essai differe HTTP='+str(code)+' type='+error,flush=True)
        c.commit();time.sleep(60/RATE)

def main():
    if not URL.startswith(('http://','https://')): raise SystemExit('Webhook absent ou invalide')
    if '--test' in sys.argv:
        import uuid
        sid='SOC-COMPLET-'+uuid.uuid4().hex[:12]
        a=dict(id=sid,timestamp=datetime.now(timezone.utc).isoformat(),rule=dict(id='100211',level=12,description='TEST COMPLET SOC - '+sid,groups=['soc_test']),
               agent=dict(id='002',name='LAB-TEST',ip='192.0.2.20'),manager=dict(name='LAB-SOC'),data=dict(src_ip='1.1.1.1',dest_ip='192.0.2.20'),full_log='Test synthetique, aucune attaque reelle.')
        code,error=post_json(URL,wazuh_to_exec(a));print('Test :',sid,'HTTP :',code,'Type :',error)
        raise SystemExit(0 if 200<=code<300 else 1)
    os.umask(0o077);c=connect()
    threading.Thread(target=drain,daemon=True).start()
    print('[START] file persistante ; debit maximum='+str(RATE)+'/minute',flush=True)
    while True:
        # Relecture des 200 dernieres lignes apres reconnexion, dedupliquees dans SQLite.
        proc=subprocess.Popen(['docker','exec',CONTAINER,'tail','-n',os.environ.get('SOC_TAIL_LINES','200'),'-F',ALERT_FILE],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        try:
            for line in proc.stdout:
                try: enqueue(c,json.loads(line))
                except (ValueError,TypeError,AttributeError): print('[Wazuh] ligne non exploitable',flush=True)
        finally:
            if proc.poll() is None: proc.terminate()
        print('[Wazuh] reconnexion dans 5 secondes',flush=True);time.sleep(5)

if __name__=='__main__': main()
