#!/usr/bin/env python3
"""Validate the delivered client TLS bridge with the real certificate helper."""
import argparse,json,os,socket,subprocess,tempfile,time
from pathlib import Path
import test_gost as t

def main():
    p=argparse.ArgumentParser();p.add_argument('--gost',required=True);p.add_argument('--config-cli',required=True);p.add_argument('--cert-helper',required=True)
    a=p.parse_args();a.gost=str(Path(a.gost).resolve());a.config_cli=str(Path(a.config_cli).resolve());a.cert_helper=str(Path(a.cert_helper).resolve())
    with tempfile.TemporaryDirectory() as td,t.serve(t.TCP((t.HOST,0),t.Echo)) as echo:
        folder=Path(td)/'leaf'
        subprocess.run([a.cert_helper,'--host',t.HOST,'--out',str(folder)],check=True,capture_output=True)
        tlsport=t.port()
        with t.Engine(a,{'socks-tls':tlsport,'cert':str(folder/'cert.pem'),'key':str(folder/'key.pem')}) as server:
            config=json.loads((Path(__file__).parent.parent/'examples'/'client-socks-tls.json').read_text())
            socks_port,http_port=t.port(),t.port()
            config['services'][0]['addr']=f'127.0.0.1:{socks_port}'
            config['services'][1]['addr']=f'127.0.0.1:{http_port}'
            node=config['chains'][0]['hops'][0]['nodes'][0]
            node['addr']=f'127.0.0.1:{tlsport}'
            node['connector']['auth']={'username':t.USER.decode(),'password':t.PASSWORD.decode()}
            node['dialer']['tls'].update({'serverName':t.HOST,'caFile':str(folder/'cert.pem')})
            with tempfile.TemporaryFile() as log:
                engine=subprocess.Popen([a.gost,'-C','-'],stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT,cwd=td,env={**os.environ,'HOME':td})
                engine.stdin.write(json.dumps(config).encode());engine.stdin.close()
                try:
                    for _ in range(100):
                        assert engine.poll() is None
                        try:
                            s=socket.create_connection((t.HOST,socks_port),timeout=.2);s.close();break
                        except OSError:time.sleep(.025)
                    with socket.create_connection((t.HOST,socks_port),timeout=5) as s:
                        s.sendall(b'\x05\x01\x00');assert t.exact(s,2)==b'\x05\x00'
                        s.sendall(b'\x05\x01\x00'+t.addr(t.HOST,echo));assert t.reply(s)[0]==0
                        data=os.urandom(10000);s.sendall(data);assert t.exact(s,len(data))==data
                    s,h=t.tunnel(http_port,t.HOST,echo,auth=b'');assert b' 200 ' in h;t.exchange(s)
                    print('PASS: delivered client template forwards local SOCKS5 and HTTP through verified TLS using generated leaf certificate.')
                finally:
                    engine.terminate();engine.wait(timeout=4)
if __name__=='__main__':main()
