#!/usr/bin/env python3
"""Functional regression tests of the shipped GOST configuration, all on loopback.
Usage: python tests/test_gost.py --gost PATH --config-cli PATH
Uses Python stdlib plus openssl command for ephemeral test certificates.
Does not load real proxy.ini, change firewall, or access Telegram/Internet.
"""
import argparse, base64, concurrent.futures, contextlib, hashlib, http.client
import http.server, json, os, socket, socketserver, ssl, struct, subprocess
import tempfile, threading, time
from pathlib import Path

HOST='127.0.0.1'; USER=b'testuser'; PASSWORD=b'test-only-123!'
AUTH=b'Proxy-Authorization: Basic '+base64.b64encode(USER+b':'+PASSWORD)+b'\r\n'
M_AUTH='Basic '+base64.b64encode(b'metrics:test-metrics-secret').decode()
RESULTS=[]

def check(name, func):
    func(); RESULTS.append(name); print('PASS '+name,flush=True)

def port():
    with socket.socket() as s:
        s.bind((HOST,0)); return s.getsockname()[1]

def exact(s,n):
    out=b''
    while len(out)<n:
        b=s.recv(n-len(out))
        if not b: raise AssertionError('unexpected EOF')
        out+=b
    return out

def headers(s):
    out=b''
    while not out.endswith(b'\r\n\r\n'):
        out+=exact(s,1)
        assert len(out)<65536
    return out

def received(s):
    out=b''
    while True:
        b=s.recv(65536)
        if not b:return out
        out+=b

def auth_socks(s,password=PASSWORD):
    for b in b'\x05\x01\x02':s.sendall(bytes([b]))
    assert exact(s,2)==b'\x05\x02'
    s.sendall(b'\x01'+bytes([len(USER)])+USER+bytes([len(password)])+password)
    return exact(s,2)

def addr(host,p):
    try: a=b'\x01'+socket.inet_aton(host)
    except OSError:a=b'\x03'+bytes([len(host)])+host.encode()
    return a+struct.pack('!H',p)

def reply(s):
    h=exact(s,4)
    if h[3]==1:host=socket.inet_ntoa(exact(s,4))
    elif h[3]==4:host=socket.inet_ntop(socket.AF_INET6,exact(s,16))
    elif h[3]==3:host=exact(s,exact(s,1)[0]).decode()
    else:raise AssertionError(h)
    return h[1],host,struct.unpack('!H',exact(s,2))[0]

def socks(p,dest,dp,context=None):
    s=socket.create_connection((HOST,p),timeout=5)
    try:
        if context:s=context.wrap_socket(s,server_hostname=HOST)
        assert auth_socks(s)==b'\x01\x00'
        s.sendall(b'\x05\x01\x00'+addr(dest,dp))
        r=reply(s);assert r[0]==0,r
        return s
    except BaseException:s.close();raise

def tunnel(p,dest,dp,context=None,auth=AUTH):
    s=socket.create_connection((HOST,p),timeout=5)
    if context:s=context.wrap_socket(s,server_hostname=HOST)
    authority=f'{dest}:{dp}'.encode()
    s.sendall(b'CONNECT '+authority+b' HTTP/1.1\r\nHost: '+authority+b'\r\n'+auth+b'\r\n')
    h=headers(s)
    return s,h

def udp_association(p,context=None):
    s=socket.create_connection((HOST,p),timeout=5)
    if context:s=context.wrap_socket(s,server_hostname=HOST)
    assert auth_socks(s)==b'\x01\x00'
    s.sendall(b'\x05\x03\x00'+addr('0.0.0.0',0))
    status,host,rp=reply(s)
    return s,status,(HOST if host=='0.0.0.0' else host,rp)

class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address=True;daemon_threads=True
class UDP(socketserver.ThreadingUDPServer):
    allow_reuse_address=True;daemon_threads=True
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while True:
                b=self.request.recv(65536)
                if not b:return
                self.request.sendall(b)
        except OSError:pass
class DatagramEcho(socketserver.BaseRequestHandler):
    def handle(self):
        b,s=self.request;s.sendto(b,self.client_address)
class Web(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*a):pass
    def do_GET(self):
        assert self.headers.get('Proxy-Authorization') is None
        assert self.headers.get('X-Remove') is None
        b=('GET '+self.path).encode()
        self.send_response(200);self.send_header('Content-Length',str(len(b)))
        self.send_header('Connection','close');self.end_headers();self.wfile.write(b)
    def do_POST(self):
        assert self.headers.get('Proxy-Authorization') is None
        if self.headers.get('Transfer-Encoding')=='chunked':
            body=b''
            while True:
                n=int(self.rfile.readline().strip(),16)
                if not n:self.rfile.readline();break
                body+=self.rfile.read(n);self.rfile.read(2)
        else:body=self.rfile.read(int(self.headers['Content-Length']))
        b=hashlib.sha256(body).hexdigest().encode()
        self.send_response(200);self.send_header('Content-Length',str(len(b)))
        self.send_header('Connection','close');self.end_headers();self.wfile.write(b)

def query(name='remote.invalid'):
    return b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\x00\x00\x01\x00\x01'

def dns_answer(b):
    # Test fixture supports one A query and returns no AAAA answers.
    end=12
    while b[end]:end+=b[end]+1
    end+=5
    q=b[12:end]
    if q[-4:-2]!=b'\x00\x01':return b[:2]+b'\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00'+q
    return b[:2]+b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'+q+b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\x7f\x00\x00\x01'
def assert_dns_answer(response, request):
    # DNS proxies can legitimately recompress names and update cached TTLs.
    # Compare the transaction, question and A record instead of wire bytes.
    assert response[:2]==request[:2] and response[2]&128 and response[3]&15==0
    qd,an=struct.unpack('!HH',response[4:8]);assert qd==1 and an==1
    def skip_name(i):
        while response[i]:
            if response[i]&0xC0==0xC0:return i+2
            i+=response[i]+1
        return i+1
    i=skip_name(12);assert response[i:i+4]==b'\x00\x01\x00\x01';i+=4
    i=skip_name(i);typ,cls,ttl,n=struct.unpack('!HHIH',response[i:i+10]);i+=10
    assert typ==1 and cls==1 and n==4 and response[i:i+n]==socket.inet_aton(HOST)

class DNSUDP(socketserver.BaseRequestHandler):
    def handle(self):
        b,s=self.request;s.sendto(dns_answer(b),self.client_address)
class DNSTCP(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while True:
                n=struct.unpack('!H',exact(self.request,2))[0];b=exact(self.request,n);r=dns_answer(b)
                self.request.sendall(struct.pack('!H',len(r))+r)
        except (OSError,AssertionError):pass
class DoH(http.server.BaseHTTPRequestHandler):
    def log_message(self,*a):pass
    def do_POST(self):
        b=self.rfile.read(int(self.headers['Content-Length']));r=dns_answer(b)
        self.send_response(200);self.send_header('Content-Type','application/dns-message')
        self.send_header('Content-Length',str(len(r)));self.end_headers();self.wfile.write(r)

@contextlib.contextmanager
def serve(server):
    t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
    try:yield server.server_address[1]
    finally:server.shutdown();server.server_close()

class Engine:
    instances=[]
    def __init__(self,args,overrides=None,env=None):
        self.socks=port();self.http=port();self.metrics=port();self.dir=tempfile.TemporaryDirectory()
        self.proc=None;self.log=None;self.closed=False
        try:
            flags={'socks':self.socks,'http':self.http,'metrics':self.metrics,**(overrides or {})}
            self.raw=subprocess.check_output([args.config_cli]+[f'{k}={v}' for k,v in flags.items()])
            self.config=json.loads(self.raw)
            clean={k:v for k,v in os.environ.items() if not k.upper().startswith(('GOST_','MTG_'))}
            clean.update({'HOME':self.dir.name,**(env or {})})
            self.log=tempfile.TemporaryFile()
            self.proc=subprocess.Popen([args.gost,'-C','-'],stdin=subprocess.PIPE,stdout=self.log,stderr=subprocess.STDOUT,cwd=self.dir.name,env=clean)
            self.instances.append(self)
            self.proc.stdin.write(self.raw);self.proc.stdin.close()
        except BaseException:self.close();raise
    def ready(self):
        for _ in range(120):
            if self.proc.poll() is not None:
                self.log.seek(0);raise AssertionError(self.log.read().decode())
            try:
                status,data=self.metrics_request()
                if status==200 and 'gost_services' in data:return self
            except OSError:pass
            time.sleep(.025)
        raise AssertionError('engine did not become ready')
    def metrics_request(self,auth=M_AUTH):
        h=http.client.HTTPConnection(HOST,self.metrics,timeout=2)
        try:
            h.request('GET','/metrics',headers={'Authorization':auth} if auth else {})
            r=h.getresponse();return r.status,r.read().decode()
        finally:h.close()
    def __enter__(self):
        try:return self.ready()
        except BaseException:self.close();raise
    def __exit__(self,*a):self.close()
    def close(self):
        if self.closed:return
        try:
            if self.proc is not None:
                if self.proc.poll() is None:
                    self.proc.terminate()
                    try:self.proc.wait(timeout=4)
                    except subprocess.TimeoutExpired:self.proc.kill();self.proc.wait(timeout=4)
                if self.proc.stdin and not self.proc.stdin.closed:self.proc.stdin.close()
        finally:
            if self.log:self.log.close()
            self.dir.cleanup();self.closed=True

def refused(p,payload,source=HOST):
    # A rejected TCP connection must close promptly, not consume a slot forever.
    with socket.create_connection((HOST,p),timeout=3,source_address=(source,0)) as s:
        assert s.getsockname()[0]==source
        try:
            s.sendall(payload)
            assert s.recv(1)==b'', 'rejected connection received protocol data'
        except (ConnectionResetError,ConnectionAbortedError,BrokenPipeError):pass

def engine_cleanup():
    endpoints=set()
    for e in Engine.instances:
        assert e.closed and e.proc.poll() is not None, 'owned GOST process is still running'
        assert e.proc.stdin.closed and e.log.closed and not Path(e.dir.name).exists()
        endpoints.add((socket.SOCK_STREAM,HOST,e.metrics))
        for service in e.config['services']:
            host,p=service['addr'].rsplit(':',1)
            udp=service['listener'].get('metadata',{}).get('mode')=='udp'
            endpoints.add((socket.SOCK_DGRAM if udp else socket.SOCK_STREAM,host,int(p)))
    for kind,host,p in endpoints:
        with socket.socket(socket.AF_INET,kind) as s:
            # Ignore TIME_WAIT after completed TCP sessions, but an active
            # listener would still prevent bind/listen without SO_REUSEPORT.
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            s.bind((host,p))
            if kind==socket.SOCK_STREAM:s.listen()

def exchange(s,n=65537):
    data=os.urandom(n)
    # Read concurrently to exercise bidirectional buffering above socket buffers.
    with concurrent.futures.ThreadPoolExecutor(1) as pool:
        f=pool.submit(exact,s,len(data));s.sendall(data);assert f.result(timeout=10)==data
    s.close()

def udp_exchange(p,dest,dp,payload,context=None):
    control,status,relay=udp_association(p,context);assert status==0
    try:
        assert 20000<=relay[1]<=20100,relay
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as u:
            u.settimeout(4);u.sendto(b'\x00\x00\x00'+addr(dest,dp)+payload,relay)
            packet,_=u.recvfrom(65535)
            n=10 if packet[3]==1 else 7+packet[4]
            assert packet[n:]==payload,(packet,payload)
    finally:control.close()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--gost',required=True);parser.add_argument('--config-cli',required=True)
    args=parser.parse_args();args.gost=str(Path(args.gost).resolve());args.config_cli=str(Path(args.config_cli).resolve())
    with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
        cert=str(Path(td)/'cert.pem');key=str(Path(td)/'key.pem')
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:TRUE','-keyout',key,'-out',cert],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
        sc=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);sc.load_cert_chain(cert,key)
        trusted=ssl.create_default_context(cafile=cert)
        echo=stack.enter_context(serve(TCP((HOST,0),Echo)))
        udp=stack.enter_context(serve(UDP((HOST,0),DatagramEcho)))
        web=stack.enter_context(serve(TCP((HOST,0),Web)))
        dns=stack.enter_context(serve(UDP((HOST,0),DNSUDP)))
        dns_tcp=stack.enter_context(serve(TCP((HOST,0),DNSTCP)))
        tls_web=TCP((HOST,0),Web);tls_web.socket=sc.wrap_socket(tls_web.socket,server_side=True)
        secureweb=stack.enter_context(serve(tls_web))
        dot_server=TCP((HOST,0),DNSTCP);dot_server.socket=sc.wrap_socket(dot_server.socket,server_side=True)
        dot=stack.enter_context(serve(dot_server))
        doh_server=TCP((HOST,0),DoH);doh_server.socket=sc.wrap_socket(doh_server.socket,server_side=True)
        doh=stack.enter_context(serve(doh_server))
        with Engine(args) as e:
            check('SOCKS5 authenticated TCP and 1 MiB integrity',lambda:exchange(socks(e.socks,HOST,echo),1024*1024))
            def wrong_socks():
                with socket.create_connection((HOST,e.socks),timeout=4) as s:assert auth_socks(s,b'incorrect')!=b'\x01\x00'
            check('SOCKS5 rejects incorrect password',wrong_socks)
            def anonymous():
                with socket.create_connection((HOST,e.socks),timeout=4) as s:s.sendall(b'\x05\x01\x00');assert exact(s,2)==b'\x05\xff'
            check('SOCKS5 refuses anonymous authentication',anonymous)
            def http_connect():
                s,h=tunnel(e.http,HOST,echo);assert b' 200 ' in h;exchange(s)
            check('HTTP CONNECT authenticated byte tunnel',http_connect)
            def http_unauth():
                s,h=tunnel(e.http,HOST,echo,auth=b'');assert b' 407 ' in h;s.close()
            check('HTTP CONNECT challenges missing credentials',http_unauth)
            def http_wrong():
                s,h=tunnel(e.http,HOST,echo,auth=b'Proxy-Authorization: Basic '+base64.b64encode(b'testuser:bad')+b'\r\n');assert b' 407 ' in h;s.close()
            check('HTTP CONNECT rejects incorrect credentials',http_wrong)
            def get():
                s=socket.create_connection((HOST,e.http),timeout=5)
                s.sendall(f'GET http://{HOST}:{web}/hello?q=1 HTTP/1.1\r\nHost: {HOST}:{web}\r\n'.encode()+AUTH+b'Connection: X-Remove, close\r\nX-Remove: forbidden\r\n\r\n')
                r=http.client.HTTPResponse(s);r.begin();assert r.status==200;assert r.read()==b'GET /hello?q=1';s.close()
            check('HTTP absolute URI forwarding strips proxy and hop headers',get)
            def chunked():
                s=socket.create_connection((HOST,e.http),timeout=5)
                s.sendall(f'POST http://{HOST}:{web}/ HTTP/1.1\r\nHost: {HOST}:{web}\r\n'.encode()+AUTH+b'Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n')
                r=http.client.HTTPResponse(s);r.begin();assert r.status==200;assert r.read()==hashlib.sha256(b'hello world').hexdigest().encode();s.close()
            check('HTTP chunked POST passes intact',chunked)
            def https_destination():
                s,h=tunnel(e.http,HOST,secureweb);assert b' 200 ' in h
                with trusted.wrap_socket(s,server_hostname=HOST) as t:
                    t.sendall(b'GET /encrypted HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');assert b'GET /encrypted' in received(t)
            check('HTTPS destination through HTTP CONNECT verifies origin TLS',https_destination)
            check('SOCKS5 UDP ASSOCIATE relays datagrams in configured range',lambda:udp_exchange(e.socks,HOST,udp,b'UDP-integration'))
            def udp_dns():
                control,status,relay=udp_association(e.socks);assert status==0
                with control,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as u:
                    u.settimeout(4);u.sendto(b'\0\0\0'+addr(HOST,dns)+query(),relay);packet,_=u.recvfrom(4096);assert packet[10:]==dns_answer(query())
            check('DNS query and reply through SOCKS5 UDP',udp_dns)
            def spoof():
                control,status,relay=udp_association(e.socks);assert status==0
                with control,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as u:
                    u.bind(('127.0.0.2',0));u.settimeout(.25);u.sendto(b'\0\0\0'+addr(HOST,udp)+b'forbidden',relay)
                    try:u.recvfrom(4096);raise AssertionError('different client IP accepted')
                    except socket.timeout:pass
            check('UDP association rejects another source IP',spoof)
            def metrics():
                assert e.metrics_request(None)[0]==401;assert e.metrics_request('Basic xxx')[0]==401
                status,text=e.metrics_request();assert status==200
                for name in ['gost_service_requests_total','gost_service_transfer_input_bytes_total','gost_service_transfer_output_bytes_total']:
                    assert name in text,name
                assert PASSWORD.decode() not in text
            check('Real metrics require independent authentication and omit secrets',metrics)
        with Engine(args,{'allow':HOST}) as e:
            def allowed_ip():
                exchange(socks(e.socks,HOST,echo))
                s,h=tunnel(e.http,HOST,echo)
                with s:
                    assert b' 200 ' in h
                    exchange(s)
            check('Exact allowIp permits authenticated SOCKS and HTTP from matching IPv4',allowed_ip)
            def denied_ip():
                refused(e.socks,b'\x05\x01\x02','127.0.0.2')
                authority=f'{HOST}:{echo}'.encode()
                refused(e.http,b'CONNECT '+authority+b' HTTP/1.1\r\nHost: '+authority+b'\r\n'+AUTH+b'\r\n','127.0.0.2')
                assert e.proc.poll() is None
            check('Exact allowIp rejects another IPv4 for SOCKS and HTTP',denied_ip)
        def shared_cap():
            with Engine(args,{'max':2}) as e,contextlib.ExitStack() as clients:
                first=clients.enter_context(socks(e.socks,HOST,echo))
                second,h=tunnel(e.http,HOST,echo);clients.enter_context(second)
                assert b' 200 ' in h
                refused(e.socks,b'\x05\x01\x02')
                authority=f'{HOST}:{echo}'.encode()
                refused(e.http,b'CONNECT '+authority+b' HTTP/1.1\r\nHost: '+authority+b'\r\n'+AUTH+b'\r\n')
                for existing in (first,second):
                    existing.sendall(b'existing-session');assert exact(existing,16)==b'existing-session'
                first.close()
                deadline=time.monotonic()+4
                while True:
                    try:
                        replacement=socks(e.socks,HOST,echo)
                        clients.enter_context(replacement)
                        break
                    except (OSError,AssertionError):
                        if time.monotonic()>=deadline:raise AssertionError('shared connection slot was not released')
                        time.sleep(.025)
                replacement.sendall(b'recovered');assert exact(replacement,9)==b'recovered'
                second.sendall(b'http-still-alive');assert exact(second,16)==b'http-still-alive'
                assert e.proc.poll() is None
        check('Shared connection cap spans SOCKS and HTTP and recovers after close',shared_cap)
        def occupied():
            with socket.socket() as s:
                s.bind((HOST,0));s.listen();e=Engine(args,{'socks':s.getsockname()[1]})
                try:assert e.proc.wait(timeout=4)!=0
                finally:e.close()
        check('Occupied listener causes startup failure',occupied)
        for upstream in [f'udp://{HOST}:{dns}',f'tcp://{HOST}:{dns_tcp}']:
            with Engine(args,{'dns':upstream,'dns-port':port()}) as e:
                check('SOCKS destination DNS via '+upstream.split(':')[0],lambda:exchange(socks(e.socks,'remote.invalid',echo)))
                check('SOCKS UDP destination DNS via '+upstream.split(':')[0],lambda:udp_exchange(e.socks,'remote.invalid',udp,b'UDP-domain'))
                dp=next(x for x in e.config['services'] if x['name']=='dns-udp')['addr'].split(':')[-1]
                def local_dns():
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as u:
                        u.settimeout(4);u.sendto(query(),(HOST,int(dp)));r,_=u.recvfrom(4096);assert_dns_answer(r,query())
                    with socket.create_connection((HOST,int(dp)),timeout=4) as s:
                        q=query();s.sendall(struct.pack('!H',len(q))+q);r=exact(s,struct.unpack('!H',exact(s,2))[0]);assert_dns_answer(r,q)
                check('Local DNS UDP and TCP via '+upstream.split(':')[0],local_dns)
        tls_ports={'https':port(),'socks-tls':port(),'cert':cert,'key':key}
        with Engine(args,tls_ports) as e:
            def https_proxy():
                s,h=tunnel(tls_ports['https'],HOST,echo,trusted);assert b' 200 ' in h;exchange(s)
            check('HTTPS proxy outer TLS with trusted SAN certificate',https_proxy)
            check('SOCKS5 over outer TLS with authenticated connection',lambda:exchange(socks(tls_ports['socks-tls'],HOST,echo,trusted)))
            def tls_reject():
                with socket.create_connection((HOST,tls_ports['https']),timeout=4) as s:
                    try:ssl.create_default_context().wrap_socket(s,server_hostname=HOST);raise AssertionError('untrusted certificate accepted')
                    except ssl.SSLCertVerificationError:pass
            check('Client rejects untrusted proxy TLS certificate',tls_reject)
            check('SOCKS TLS control plus standard UDP relay',lambda:udp_exchange(tls_ports['socks-tls'],HOST,udp,b'plain-udp-documented',trusted))
        for kind in ['socks5','http']:
            with Engine(args,{'user':'upuser','password':'upstream-only-123!','dns':f'udp://{HOST}:{dns}'}) as up:
                cp=port();hp=port()
                chain={'chain-socks':cp,'chain-http':hp,'up-type':kind,'up-host':HOST,'up-port':up.socks if kind=='socks5' else up.http,'up-user':'upuser','up-pass':'upstream-only-123!'}
                with Engine(args,chain) as front:
                    check('Chained SOCKS TCP through '+kind+' with remote DNS',lambda:exchange(socks(cp,'remote.invalid',echo)))
                    def chained_http():
                        s,h=tunnel(hp,'remote.invalid',echo);assert b' 200 ' in h;exchange(s)
                    check('Chained HTTP CONNECT through '+kind+' with separate upstream credentials',chained_http)
                    check('Direct ports remain independent of '+kind+' chain',lambda:exchange(socks(front.socks,HOST,echo)))
                    with Engine(args,{**chain,'https':port(),'tls-chain':1,'cert':cert,'key':key,'chain-socks':port(),'chain-http':port()}) as securefront:
                        def chained_tls():
                            p=int(next(x for x in securefront.config['services'] if x['name']=='tls-http')['addr'].rsplit(':',1)[1])
                            s,h=tunnel(p,'remote.invalid',echo,trusted);assert b' 200 ' in h;exchange(s)
                        check('HTTPS proxy TLS routes through '+kind+' upstream',chained_tls)
                    if kind=='socks5':check('Standard UDP ASSOCIATE through SOCKS upstream',lambda:udp_exchange(cp,'remote.invalid',udp,b'chained-udp'))
                    else:
                        def http_no_udp():
                            c,status,_=udp_association(cp);c.close();assert status!=0
                        check('HTTP upstream refuses unsupported UDP',http_no_udp)
                    up.close()
                    def fail_closed():
                        for _ in range(4):
                            s,h=tunnel(hp,HOST,echo);assert b' 200 ' not in h;s.close()
                    check('No direct fallback after '+kind+' upstream failure',fail_closed)
        for scheme,dest in [('tls',dot),('https',doh)]:
            uri=f'{scheme}://localhost:{dest}'+('/dns-query' if scheme=='https' else '')
            with Engine(args,{'dns':uri},env={'SSL_CERT_FILE':cert}) as e:
                check('Verified '+scheme+' DNS resolves through trusted test CA',lambda:exchange(socks(e.socks,'remote.invalid',echo)))
            with Engine(args,{'dns':uri,'timeout':2},env={'SSL_CERT_FILE':'/dev/null','SSL_CERT_DIR':td+'/empty'}) as e:
                def reject_dns_tls():
                    s=socket.create_connection((HOST,e.socks),timeout=5);assert auth_socks(s)==b'\x01\x00'
                    s.sendall(b'\x05\x01\x00'+addr('remote.invalid',echo));status,_,_=reply(s);s.close();assert status!=0
                check('Untrusted '+scheme+' DNS certificate fails closed',reject_dns_tls)
        def invalid():
            for values in [('socks=1080','http=1080'),('password=short',),('allow=1.2.3',),('dns=ftp://127.0.0.1',),('udp-min=21000','udp-max=20000'),('https=8443',),('chain-http=8081','up-host=127.0.0.1','up-port=8081')]:
                r=subprocess.run([args.config_cli,*values],capture_output=True);assert r.returncode!=0,values
        check('Validation rejects port conflicts, weak format, invalid DNS/TLS/chain/range',invalid)
    check('All owned engine processes exit and listener ports can be reused',engine_cleanup)
    print(f'RESULT: {len(RESULTS)} functional groups passed. No external endpoints used.',flush=True)

if __name__=='__main__':main()
