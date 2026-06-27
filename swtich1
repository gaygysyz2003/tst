import socket, time, json, os, threading
from datetime import datetime, timedelta

SWITCH_IP = "10.252.254.8"
SWITCH_PORT = 3082
SWITCH_USER = "root"
SWITCH_PASS = "root"
TOTAL_PORTS = 114
TIMEOUT = 30
READ_PAUSE = 1.5
MAX_TRIES = 4
TIMER_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "patch_timers.json")
G = "\033[92m"
Y = "\033[93m"
R = "\033[91m"
C = "\033[96m"
B = "\033[1m"
X = "\033[0m"
D = "\033[2m"
patch_timers = {}
lock = threading.Lock()

def load():
    global patch_timers
    if os.path.exists(TIMER_FILE):
        try:
            with open(TIMER_FILE,"r") as f: patch_timers = json.load(f)
        except: patch_timers = {}

def save():
    with open(TIMER_FILE,"w") as f: json.dump(patch_timers,f)

def tkey(a,b): return f"{min(a,b)}-{max(a,b)}"

def fmt(s):
    if s is None: return "no timer"
    if s<=0: return R+"EXPIRED"+X
    h=s//3600; m=(s%3600)//60; sc=s%60
    t=f"{h}h{m}m" if h>0 else (f"{m}m{sc}s" if m>0 else f"{sc}s")
    return (Y if s<1800 else G)+t+X

def conn():
    import re as _re
    sock = socket.create_connection((SWITCH_IP, SWITCH_PORT), 10)
    sock.settimeout(10)
    _send_read(sock, "act-user::root:1::root;")
    return sock

def _send_read(sock, cmd):
    import re as _re
    if not cmd.endswith(";"): cmd += ";"
    sock.sendall((cmd + "\r\n").encode("ascii"))
    buf = ""
    while True:
        try:
            chunk = sock.recv(4096).decode("ascii", errors="replace")
        except socket.timeout:
            break
        if not chunk: break
        buf += chunk
        if _re.search(r"(?m)^\s*;\s*$", buf): break
    return buf

def login(s): return True
def rd(s, cmd):
    return _send_read(s, cmd)

def rw(s,cmd):
    s.sendall((cmd+"\r\n").encode()); time.sleep(READ_PAUSE); r=b""
    try:
        s.settimeout(1.0)
        while True:
            c=s.recv(4096)
            if not c: break
            r+=c
    except socket.timeout: pass
    finally: s.settimeout(TIMEOUT)
    return r.decode(errors="replace")

def get_patches():
    try:
        s=conn()
        if not login(s): return None,"Login failed"
        r=rd(s,"rtrv-patch:::1:;"); s.close()
        patches=[]
        for line in r.splitlines():
            line=line.strip().strip('"')
            import re as _re
            m = _re.match(r'(\d+)\s*,\s*(\d+)', line)
            if m:
                try: patches.append((int(m.group(1)), int(m.group(2))))
                except ValueError: pass
        return patches,None
    except Exception as e: return None,str(e)

def get_power():
    try:
        s=conn()
        if not login(s): return None,"Login failed"
        rd(s,"set-port-pmon::1&&114:1:::wave=1310;")
        r=rd(s,"rtrv-port-pmon::1&&114:1:;")
        s.close()
        out={}
        import re as _re
        for line in r.splitlines():
            line=line.strip().strip('"')
            m=_re.match(r'(\d+):([\d.]+),([\d.-]+),(\d+)', line)
            if m:
                try: out[int(m.group(1))]=float(m.group(3))
                except: pass
        return out,None
    except Exception as e: return None,str(e)

def mk_patch(a,b):
    try:
        s=conn()
        if not login(s): return False,"Login failed"
        cmd=f"ent-patch::{a},{b}:1:;"
        for i in range(1,MAX_TRIES+1):
            rw(s,cmd); time.sleep(READ_PAUSE)
            v=rd(s,"rtrv-patch:::1:;")
            if f"{a},{b}" in v or f"{b},{a}" in v: s.close(); return True,None
            print(f"  Retry {i}/{MAX_TRIES}...")
        s.close(); return False,"Not confirmed"
    except Exception as e: return False,str(e)
def dl_patch(a,b):
    try:
        s=conn()
        if not login(s): return False,"Login failed"
        cmd=f"dlt-patch::{a}&{b}:1:;"
        for i in range(1,MAX_TRIES+1):
            rw(s,cmd); time.sleep(READ_PAUSE)
            v=rd(s,"rtrv-patch:::1:;")
            if f"{a},{b}" not in v and f"{b},{a}" not in v: s.close(); return True,None
            print(f"  Retry {i}/{MAX_TRIES}...")
        s.close(); return False,"Still present"
    except Exception as e: return False,str(e)

def watcher():
    while True:
        time.sleep(30); now=datetime.utcnow()
        with lock:
            exp=[k for k,v in patch_timers.items() if datetime.fromisoformat(v["expires"])<=now]
        for key in exp:
            try:
                a,b=map(int,key.split("-"))
                ok,err=dl_patch(a,b)
                print(f"\n{Y}[AUTO-UNPATCH]{X} {a}<->{b}: {'OK' if ok else err}")
            except Exception as e: print(f"\n{R}[ERROR]{X} {key}: {e}")
            with lock: patch_timers.pop(key,None); save()

def clr(): os.system("clear")
def hdr():
    print(B+C+"="*50)
    print("  Switch 1 Polatis - Patch Manager")
    print(D+f"  {SWITCH_IP} | {TOTAL_PORTS} ports | TL1"+X)
    print(B+C+"="*50+X); print()
def err(m): print(f"\n{R}ERROR:{X} {m}")
def ok(m): print(f"\n{G}OK:{X} {m}")
def wait(): input(f"\n{D}Press Enter...{X}")

def show_ports():
    clr(); hdr(); print(B+"All Ports"+X); print()
    print("  Fetching...",end="",flush=True)
    patches,e=get_patches()
    if patches is None: err(e); wait(); return
    pm={}
    for a,b in patches: pm[a]=b; pm[b]=a
    now=datetime.utcnow()
    print(f"\r  {G}OK{X} - {len(patches)} patches\n")
    print(f"  {G}###{X}=Patched  {Y}###{X}=Expiring  {D}###{X}=Free\n")
    for rs in range(1,TOTAL_PORTS+1,10):
        row=""
        for p in range(rs,min(rs+10,TOTAL_PORTS+1)):
            if p in pm:
                k=tkey(p,pm[p])
                with lock: ti=patch_timers.get(k)
                if ti:
                    secs=max(0,int((datetime.fromisoformat(ti["expires"])-now).total_seconds()))
                    col=Y if secs<1800 else G
                else: col=G
                row+=f"  {col}{p:>3}{X}"
            else: row+=f"  {D}{p:>3}{X}"
        print(row)
    print(); print(B+"Active Patches:"+X)
    if not patches: print(f"  {D}None{X}")
    else:
        print(f"  {'A':<6} {'B':<6} {'Label':<18} Time"); print("  "+"-"*40)
        seen=set()
        for a,b in patches:
            k=tkey(a,b)
            if k in seen: continue
            seen.add(k)
            with lock: ti=patch_timers.get(k)
            if ti:
                secs=max(0,int((datetime.fromisoformat(ti["expires"])-now).total_seconds()))
                ts=fmt(secs); lb=ti.get("label","")
            else: ts=D+"no timer"+X; lb=""
            print(f"  {a:<6} {b:<6} {lb:<18} {ts}")
    wait()

def make_patch():
    clr(); hdr(); print(B+"Create Patch"+X); print()
    print("  Fetching...",end="",flush=True)
    patches,e=get_patches()
    if patches is None: err(e); wait(); return
    ps=set()
    for a,b in patches: ps.add(a); ps.add(b)
    up=[p for p in range(1,TOTAL_PORTS+1) if p not in ps]
    print(f"\r  {G}OK{X} - {len(up)} free ports\n")
    print(f"  Free: {D}{', '.join(str(p) for p in up)}{X}\n")
    try:
        a=int(input("  Port A: "))
        b=int(input("  Port B: "))
    except: err("Invalid"); wait(); return
    if a==b: err("Same port"); wait(); return
    if a in ps or b in ps: err("Already patched"); wait(); return
    if not(1<=a<=TOTAL_PORTS) or not(1<=b<=TOTAL_PORTS): err(f"Ports 1-{TOTAL_PORTS}"); wait(); return
    try: d=int(input("  Duration (minutes): "))
    except: err("Invalid"); wait(); return
    lb=input("  Label (optional): ").strip()
    print(f"\n  Creating {a}<->{b} for {d} min...")
    ok_,e=mk_patch(a,b)
    if not ok_: err(e); wait(); return
    exp=(datetime.utcnow()+timedelta(minutes=d)).isoformat()
    k=tkey(a,b)
    with lock: patch_timers[k]={"expires":exp,"label":lb}; save()
    ok(f"Port {a}<->{b} patched for {d} min!"); wait()

def remove_patch():
    clr(); hdr(); print(B+"Remove Patch"+X); print()
    print("  Fetching...",end="",flush=True)
    patches,e=get_patches()
    if patches is None: err(e); wait(); return
    print(f"\r  {G}OK{X}\n")
    if not patches: print(f"  {D}No patches{X}"); wait(); return
    now=datetime.utcnow(); seen=set(); num=[]
    for a,b in patches:
        k=tkey(a,b)
        if k in seen: continue
        seen.add(k); num.append((a,b))
    print(f"  {'#':<4} {'A':<6} {'B':<6} {'Label':<18} Time"); print("  "+"-"*45)
    for i,(a,b) in enumerate(num,1):
        k=tkey(a,b)
        with lock: ti=patch_timers.get(k)
        if ti:
            secs=max(0,int((datetime.fromisoformat(ti["expires"])-now).total_seconds()))
            ts=fmt(secs); lb=ti.get("label","")
        else: ts=D+"no timer"+X; lb=""
        print(f"  {i:<4} {a:<6} {b:<6} {lb:<18} {ts}")
    print()
    try: c=int(input("  Number to remove (0=cancel): "))
    except: return
    if c==0: return
    if not(1<=c<=len(num)): err("Invalid"); wait(); return
    a,b=num[c-1]
    if input(f"  Remove {a}<->{b}? (yes/no): ").strip().lower()!="yes": return
    print(f"  Removing {a}<->{b}...")
    ok_,e=dl_patch(a,b)
    if not ok_: err(e); wait(); return
    k=tkey(a,b)
    with lock: patch_timers.pop(k,None); save()
    ok(f"{a}<->{b} removed!"); wait()

def power_mon():
    clr(); hdr(); print(B+"Power Monitor"+X); print()
    print("  Pulling readings...",end="",flush=True)
    readings,e=get_power()
    if readings is None: err(e); wait(); return
    print(f"\r  {G}OK{X} - {len(readings)} readings\n")
    print(f"  {D}Strong>-10  Medium-10to-30  Weak<-30{X}\n")
    for rs in range(1,TOTAL_PORTS+1,8):
        row=""
        for p in range(rs,min(rs+8,TOTAL_PORTS+1)):
            pw=readings.get(p)
            if pw is not None:
                col=G if pw>-10 else(Y if pw>-30 else R)
                row+=f"  P{p:<3}{col}{pw:>7.2f}dB{X}"
            else: row+=f"  P{p:<3}{D}N/A   {X}"
        print(row)
    wait()

def main():
    load()
    threading.Thread(target=watcher,daemon=True).start()
    while True:
        clr(); hdr()
        patches,_=get_patches()
        if patches is not None:
            pc=len(set(min(a,b) for a,b in patches))
            print(f"  {G}Patched:{X} {pc*2:<4}  {D}Unpatched:{X} {TOTAL_PORTS-pc*2:<4}")
        else: print(f"  {R}Cannot reach Switch 1{X}")
        print()
        print(f"  {B}1{X}) Show all ports")
        print(f"  {B}2{X}) Create patch")
        print(f"  {B}3{X}) Remove patch")
        print(f"  {B}4{X}) Power monitor")
        print(f"  {B}5{X}) Exit"); print()
        c=input("  Choice (1-5): ").strip()
        if c=="1": show_ports()
        elif c=="2": make_patch()
        elif c=="3": remove_patch()
        elif c=="4": power_mon()
        elif c=="5": clr(); print("\n  Goodbye!\n"); break

if __name__=="__main__": main()
