#include "service_firewall.h"
#include <algorithm>
#include <iomanip>
#include <set>
#include <sstream>

namespace service_firewall {
namespace {
bool ipv4(const std::string& s) {
    unsigned parts=0, value=0, digits=0;
    for(std::size_t i=0;i<=s.size();++i) {
        const char c=i==s.size()?'.':s[i];
        if(c=='.') { if(!digits||value>255)return false; ++parts;value=0;digits=0; }
        else if(c>='0'&&c<='9') { value=value*10+static_cast<unsigned>(c-'0');if(++digits>3)return false; }
        else return false;
    }
    return parts==4;
}
std::wstring wideAscii(const std::string& s) { return std::wstring(s.begin(),s.end()); }
std::wstring normalPath(std::wstring s) {
    std::replace(s.begin(),s.end(),L'/',L'\\');
    while(s.size()>3&&s.back()==L'\\')s.pop_back();
    return s;
}
bool validDirectory(const std::wstring& s) {
    if(s.size()<4||s.size()>32000||s[1]!=L':'||s[2]!=L'\\')return false;
    if(!((s[0]>=L'A'&&s[0]<=L'Z')||(s[0]>=L'a'&&s[0]<=L'z')))return false;
    std::size_t start=3;
    for(std::size_t i=3;i<=s.size();++i) {
        if(i==s.size()||s[i]==L'\\') {
            if(i==start||s[i-1]==L'.'||s[i-1]==L' ')return false;
            start=i+1;
        } else if(s[i]<32||s[i]==L':'||s[i]==L'"'||s[i]==L'*'||s[i]==L'?'||s[i]==L'<'||s[i]==L'>'||s[i]==L'|')return false;
    }
    return true;
}
std::wstring hash(const std::wstring& s) {
    std::uint64_t h=14695981039346656037ULL;
    for(wchar_t c:s) { std::uint32_t u=static_cast<std::uint32_t>(c);for(unsigned b=0;b<4;++b){h^=u&255;h*=1099511628211ULL;u>>=8;} }
    std::wostringstream o;o<<std::hex<<std::setfill(L'0')<<std::setw(16)<<h;return o.str();
}
std::wstring lowerAscii(std::wstring s) { for(wchar_t& c:s)if(c>=L'A'&&c<=L'Z')c+=L'a'-L'A';return s; }
bool isLoopback(const std::string& ip) { return ip.compare(0,4,"127.")==0; }
bool singleHostAddress(const std::wstring& text, std::uint32_t& result) {
    const std::size_t slash=text.find(L'/');
    if(slash!=std::wstring::npos) {
        const std::wstring mask=text.substr(slash+1);
        if(mask!=L"32"&&mask!=L"255.255.255.255")return false;
    }
    const std::size_t end=slash==std::wstring::npos?text.size():slash;
    unsigned parts=0,value=0,digits=0;result=0;
    for(std::size_t i=0;i<=end;++i) {
        const wchar_t c=i==end?L'.':text[i];
        if(c==L'.') {
            if(!digits||value>255||parts>=4)return false;
            result=(result<<8)|value;++parts;value=0;digits=0;
        } else if(c>=L'0'&&c<=L'9') {
            value=value*10+static_cast<unsigned>(c-L'0');
            if(++digits>3)return false;
        } else return false;
    }
    return parts==4;
}
std::wstring address(const std::string& ip) { return ip=="0.0.0.0"?L"*":wideAscii(ip); }
void addRule(std::vector<Rule>& rules,const std::wstring& prefix,const std::wstring& kind,
             const std::wstring& program,int protocol,const std::wstring& ports,
             const std::wstring& local,const std::wstring& remote) {
    Rule r;r.application=program;r.protocol=protocol;r.localPorts=ports;r.localAddresses=local;r.remoteAddresses=remote;
    r.name=prefix+kind+L"."+hash(lowerAscii(program)+L"|"+std::to_wstring(protocol)+L"|"+ports+L"|"+local+L"|"+remote);
    rules.push_back(r);
}
}
const wchar_t* groupName() { return L"Proxy Server 2.1 - managed service"; }
const wchar_t* description() { return L"ProxyServer21 managed inbound rule v1; program and selected ports only."; }
std::wstring installationPrefix(const std::wstring& directory) { return L"ProxyServer21."+hash(lowerAscii(normalPath(directory)))+L"."; }
bool equivalentAddressScope(const std::wstring& actual,const std::wstring& expected) {
    if(actual==L"*"||expected==L"*")return actual==expected;
    std::uint32_t a=0,b=0;
    return singleHostAddress(actual,a)&&singleHostAddress(expected,b)&&a==b;
}
bool makePlan(const proxy::Config& p,const mtproto::Config& mt,const std::wstring& installDirectory,
              bool includeMTProto,std::vector<Rule>& rules,std::string& error) {
    rules.clear();error.clear();
    const std::wstring dir=normalPath(installDirectory);
    if(!validDirectory(dir)){error="FIREWALL_INSTALL_PATH";return false;}
    const bool proxyConfigured=!p.user.empty()&&!p.password.empty();
    if(!proxyConfigured&&(!p.user.empty()||!p.password.empty())){error="FIREWALL_PROXY_ACCOUNT";return false;}
    if(proxyConfigured&&(!ipv4(p.bindAddress)||(!p.allowIp.empty()&&!ipv4(p.allowIp)))){error="FIREWALL_IP";return false;}
    if(includeMTProto&&(!ipv4(mt.bindAddress)||!mt.listenPort)){error="FIREWALL_MT_PORT_OR_IP";return false;}
    const std::wstring prefix=installationPrefix(dir),gost=dir+L"\\components\\gost.exe";
    std::set<unsigned short> tcp;
    auto add=[&](bool enabled,unsigned short port)->bool {if(!enabled||!proxyConfigured)return true;if(!port)return false;tcp.insert(port);return true;};
    if(!add(p.enableSocks,p.socksPort)||!add(p.enableHttp,p.httpPort)||!add(p.enableHttps,p.httpsPort)||
       !add(p.enableSocksTls,p.socksTlsPort)||!add(p.enableChainSocks,p.chainSocksPort)||!add(p.enableChainHttp,p.chainHttpPort)){
        error="FIREWALL_TCP_PORT";return false;
    }
    const std::wstring local=address(p.bindAddress),remote=p.allowIp.empty()?L"*":wideAscii(p.allowIp);
    if(!tcp.empty()&&!isLoopback(p.bindAddress)) {
        std::wstring ports;for(unsigned short port:tcp){if(!ports.empty())ports+=L",";ports+=std::to_wstring(port);}
        addRule(rules,prefix,L"gost-tcp",gost,6,ports,local,remote);
    }
    const bool canUdp=p.enableSocks||
        (p.enableChainSocks&&p.upstreamType=="socks5")||
        (p.enableSocksTls&&(!p.tlsUseChain||p.upstreamType=="socks5"));
    if(proxyConfigured&&p.enableSocksUdp&&canUdp&&!isLoopback(p.bindAddress)) {
        if(!p.udpPortMin||p.udpPortMax<p.udpPortMin){error="FIREWALL_UDP_RANGE";rules.clear();return false;}
        std::wstring ports=std::to_wstring(p.udpPortMin);
        if(p.udpPortMax!=p.udpPortMin)ports+=L"-"+std::to_wstring(p.udpPortMax);
        addRule(rules,prefix,L"gost-udp",gost,17,ports,local,remote);
    }
    if(includeMTProto&&!isLoopback(mt.bindAddress))
        addRule(rules,prefix,L"mtg-tcp",dir+L"\\components\\mtg.exe",6,std::to_wstring(mt.listenPort),address(mt.bindAddress),L"*");
    // DNS and metrics are loopback-only and intentionally absent from this plan.
    return true;
}
}
