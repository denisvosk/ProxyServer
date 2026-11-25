#include "service_firewall.h"
#include <iostream>
#include <stdexcept>

namespace {
unsigned assertions=0;
void check(bool value,const char* message){++assertions;if(!value)throw std::runtime_error(message);}
std::vector<service_firewall::Rule> plan(proxy::Config p,mtproto::Config mt=mtproto::Config(),bool telegram=false){
    std::vector<service_firewall::Rule> r;std::string error;
    check(service_firewall::makePlan(p,mt,L"C:\\Program Files\\ProxyServer21",telegram,r,error),error.c_str());return r;
}
proxy::Config configured(){proxy::Config p;p.user="test";p.password="only_test_password";return p;}
proxy::Config none(){proxy::Config p=configured();p.enableSocks=false;p.enableHttp=false;p.enableSocksUdp=false;return p;}
void rejected(proxy::Config p,const std::wstring& directory,const char* why){
    std::vector<service_firewall::Rule> r;std::string error;
    check(!service_firewall::makePlan(p,mtproto::Config(),directory,false,r,error),why);check(!error.empty(),"missing error");
}
}
int main(){try{
    proxy::Config p=configured();auto r=plan(p);
    check(r.size()==2,"default rule count");check(r[0].protocol==6,"TCP protocol");
    check(r[0].localPorts==L"1080,8080","only selected TCP ports");
    check(r[0].application==L"C:\\Program Files\\ProxyServer21\\components\\gost.exe","exact executable");
    check(r[0].remoteAddresses==L"*"&&r[0].localAddresses==L"*","default address scope");
    check(r[1].protocol==17&&r[1].localPorts==L"20000-20100","fixed UDP range");
    check(r[0].name!=r[1].name,"distinct names");
    check(plan(proxy::Config()).empty(),"unconfigured proxy opens no ports");
    mtproto::Config onlyMt;check(plan(proxy::Config(),onlyMt,true).size()==1,"MT-only install opens only MTProto");
    auto baseline=r;
    p.socksPort=1082;r=plan(p);check(r[0].name!=baseline[0].name,"changed plan gets distinct staged rule");
    check(r[1].name==baseline[1].name,"unchanged UDP rule remains stable");
    check(service_firewall::installationPrefix(L"C:\\Program Files\\ProxyServer21\\")==
          service_firewall::installationPrefix(L"c:/program files/proxyserver21"),"case and separator stable install id");
    check(service_firewall::installationPrefix(L"C:\\One")!=service_firewall::installationPrefix(L"C:\\Two"),"distinct installations");
    p=none();p.enableDns=true;p.dnsPort=1053;r=plan(p);check(r.empty(),"no public DNS or metrics rules");
    p=configured();p.bindAddress="127.0.0.1";r=plan(p);check(r.empty(),"loopback only needs no public rules");
    p.bindAddress="127.12.34.56";check(plan(p).empty(),"entire loopback range");
    p=configured();p.bindAddress="192.0.2.4";p.allowIp="198.51.100.9";
    mtproto::Config mt;mt.bindAddress="192.0.2.5";mt.listenPort=443;r=plan(p,mt,true);
    check(r.size()==3,"telegram rule enabled");check(r[0].localAddresses==L"192.0.2.4","GOST bind scope");
    check(r[0].remoteAddresses==L"198.51.100.9"&&r[1].remoteAddresses==L"198.51.100.9","TCP and UDP client scope");
    check(r[2].localAddresses==L"192.0.2.5"&&r[2].remoteAddresses==L"*","MTProto has independent scope");
    check(r[2].application==L"C:\\Program Files\\ProxyServer21\\components\\mtg.exe","MTProto exact executable");
    check(r[2].localPorts==L"443"&&r[2].protocol==6,"MTProto TCP only");
    mt.bindAddress="127.0.0.1";check(plan(none(),mt,true).empty(),"loopback MTProto needs no public rule");
    p=none();p.enableChainSocks=true;p.enableSocksUdp=true;p.upstreamType="http";r=plan(p);
    check(r.size()==1&&r[0].localPorts==L"1081","HTTP upstream cannot relay SOCKS UDP");
    p.upstreamType="socks5";check(plan(p).size()==2,"SOCKS chain UDP enabled");
    p=none();p.enableSocksTls=true;p.enableSocksUdp=true;p.tlsUseChain=true;p.upstreamType="http";
    check(plan(p).size()==1,"TLS SOCKS over HTTP upstream no UDP");
    p.tlsUseChain=false;check(plan(p).size()==2,"direct TLS SOCKS may relay standard UDP");
    p=none();p.enableHttps=true;p.enableSocksUdp=true;
    check(plan(p).size()==1,"HTTPS does not open UDP");
    p=configured();p.udpPortMin=65535;p.udpPortMax=65535;r=plan(p);
    check(r[1].localPorts==L"65535","single UDP port");
    p.enableSocksUdp=false;r=plan(p);check(r.size()==1,"disabled UDP opens none");
    p=configured();p.socksPort=0;rejected(p,L"C:\\ProxyServer21","zero TCP port");
    p=configured();p.udpPortMin=0;rejected(p,L"C:\\ProxyServer21","zero UDP range");
    p=configured();p.udpPortMin=30000;p.udpPortMax=20000;rejected(p,L"C:\\ProxyServer21","reversed UDP range");
    p=configured();p.allowIp="198.51.100.1/24";rejected(p,L"C:\\ProxyServer21","CIDR not exact client IP");
    p.allowIp="*";rejected(p,L"C:\\ProxyServer21","wildcard injection");
    p.allowIp="1.2.3.4,Any";rejected(p,L"C:\\ProxyServer21","address list injection");
    p=configured();p.bindAddress="256.1.2.3";rejected(p,L"C:\\ProxyServer21","invalid octet");
    p.bindAddress="1.2.3";rejected(p,L"C:\\ProxyServer21","short IPv4");
    p.bindAddress=std::string("1.2.3.4\0junk",12);rejected(p,L"C:\\ProxyServer21","embedded NUL");
    p=configured();rejected(p,L"relative\\path","relative install");
    rejected(p,L"C:\\safe\\..\\Other","traversal install");
    rejected(p,L"C:\\ProxyServer21.","aliased install");
    rejected(p,L"C:\\ProxyServer21:stream","alternate data stream");
    rejected(p,L"C:\\ProxyServer21\\bad*","wildcard path");
    rejected(p,L"\\\\server\\share\\ProxyServer21","network service binaries");
    std::cout<<"service firewall plan: "<<assertions<<" assertions passed\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL: "<<e.what()<<"\n";return 1;}}
