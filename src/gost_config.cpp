#include "gost_config.h"
#include <algorithm>
#include <cctype>
#include <set>
#include <sstream>
#include <vector>

namespace proxy {
namespace {
std::string quote(const std::string& value) {
    static const char hex[]="0123456789abcdef";
    std::string out="\"";
    for(unsigned char c:value) {
        if(c=='"'||c=='\\') {out+='\\';out+=static_cast<char>(c);}
        else if(c<32) {out+="\\u00";out+=hex[c>>4];out+=hex[c&15];}
        else out+=static_cast<char>(c);
    }
    return out+'"';
}
std::string num(unsigned value) {return std::to_string(value);}
std::string boolean(bool value) {return value?"true":"false";}
std::string seconds(unsigned value) {return quote(num(value)+"s");}
std::string address(const std::string& host,unsigned short port) {
    return quote((host.find(':')!=std::string::npos?"["+host+"]":host)+":"+num(port));
}
bool ipv4(const std::string& s) {
    if(s.empty()||s.size()>15) return false;
    unsigned parts=0,value=0,digits=0;
    for(std::size_t i=0;i<=s.size();++i) {
        char c=i<s.size()?s[i]:'.';
        if(c=='.') {
            if(!digits||digits>3||value>255) return false;
            ++parts;value=0;digits=0;
        } else if(c>='0'&&c<='9') {value=value*10+static_cast<unsigned>(c-'0');++digits;}
        else return false;
    }
    return parts==4;
}
bool dnsHost(const std::string& s) {
    if(s.empty()||s.size()>253) return false;
    unsigned label=0;
    for(std::size_t i=0;i<s.size();++i) {
        unsigned char c=static_cast<unsigned char>(s[i]);
        if(c=='.') {
            if(!label||s[i-1]=='-') return false;
            label=0;
        } else {
            if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-')) return false;
            if((!label&&c=='-')||++label>63) return false;
        }
    }
    return label>0&&s.back()!='-';
}
bool printable(const std::string& s,std::size_t minimum,std::size_t maximum) {
    if(s.size()<minimum||s.size()>maximum) return false;
    return std::all_of(s.begin(),s.end(),[](unsigned char c){return c>=33&&c<=126;});
}
bool cleanPath(const std::string& s) {
    if(s.empty()||s.size()>32000) return false;
    for(unsigned char c:s) if(c<32) return false;
    // Absolute drive/UNC paths on Windows; /path for portable configuration tests.
    return s[0]=='/' || (s.size()>2&&s[1]==':'&&(s[2]=='\\'||s[2]=='/')) ||
           (s.size()>3&&s[0]=='\\'&&s[1]=='\\');
}
bool dnsUri(const std::string& s) {
    if(s.empty()) return true;
    if(s.size()>2048||s.find_first_of(" \t\r\n@#?\\")!=std::string::npos||s.find('\0')!=std::string::npos) return false;
    const auto p=s.find("://");
    if(p==std::string::npos) return false;
    const std::string scheme=s.substr(0,p);
    if(scheme!="udp"&&scheme!="tcp"&&scheme!="tls"&&scheme!="https") return false;
    const std::string remainder=s.substr(p+3);
    const auto slash=remainder.find('/');
    if(scheme!="https"&&slash!=std::string::npos) return false;
    if(scheme=="https"&&(slash==std::string::npos||slash+1==remainder.size())) return false;
    const std::string authority=remainder.substr(0,slash);
    const auto colon=authority.find(':');
    const std::string host=authority.substr(0,colon);
    if(!dnsHost(host)) return false;
    if(colon!=std::string::npos) {
        const std::string port=authority.substr(colon+1);
        if(port.empty()||port.size()>5) return false;
        unsigned n=0;
        for(char c:port) {if(c<'0'||c>'9') return false;n=n*10+static_cast<unsigned>(c-'0');}
        if(!n||n>65535) return false;
    }
    return true;
}
bool chainEnabled(const Config& c) {return c.enableChainSocks||c.enableChainHttp||((c.enableHttps||c.enableSocksTls)&&c.tlsUseChain);}
std::string auth(const std::string& user,const std::string& password) {
    return "{\"username\":"+quote(user)+",\"password\":"+quote(password)+"}";
}
std::string tls(const Config& c) {
    return "{\"certFile\":"+quote(c.tlsCertFile)+",\"keyFile\":"+quote(c.tlsKeyFile)+
           ",\"options\":{\"minVersion\":\"VersionTLS12\"}}";
}
std::string service(const Config& c,const char* name,const char* kind,unsigned short port,bool secure,bool chain) {
    // GOST's generic metadata.GetInt accepts strings but not JSON float64.
    // Encode numeric metadata as strings; structural config numbers are separate.
    const bool socks=std::string(kind)=="socks5";
    std::string out="{\"name\":"+quote(name)+",\"addr\":"+address(c.bindAddress,port)+
        ",\"climiter\":\"connections\",\"metadata\":{\"dialTimeout\":"+seconds(c.connectTimeoutSeconds)+"}";
    if(!c.allowIp.empty()) out+=",\"admission\":\"clients\"";
    // Do not resolve a target locally when the purchased proxy should resolve it.
    if(!chain&&!c.dnsServer.empty()) out+=",\"resolver\":\"dns-upstream\"";
    out+=",\"handler\":{\"type\":"+quote(kind)+",\"auth\":"+auth(c.user,c.password);
    if(chain) out+=",\"chain\":\"upstream\"";
    out+=",\"metadata\":{\"readTimeout\":"+seconds(c.connectTimeoutSeconds);
    if(socks) {
        const bool udp=c.enableSocksUdp&&(!chain||c.upstreamType=="socks5");
        out+=",\"notls\":true,\"bind\":false,\"udp\":"+boolean(udp)+
             ",\"udp.bufferSize\":\"65535\",\"udp.bindRange.min\":"+quote(num(c.udpPortMin))+
             ",\"udp.bindRange.max\":"+quote(num(c.udpPortMax));
    } else out+=",\"idleTimeout\":"+seconds(c.idleTimeoutSeconds);
    out+="}},\"listener\":{\"type\":"+quote(secure?"tls":"tcp");
    if(secure) out+=",\"tls\":"+tls(c);
    out+="}}";
    return out;
}
}

bool validate(const Config& c,std::string& error) {
    error.clear();
    auto fail=[&](const char* message)->bool{error=message;return false;};
    if(!(c.enableSocks||c.enableHttp||c.enableChainSocks||c.enableChainHttp||c.enableHttps||c.enableSocksTls||c.enableDns))
        return fail("PROTOCOLS");
    if(!printable(c.user,1,128)||c.user.find(':')!=std::string::npos)
        return fail("USER");
    if(!printable(c.password,8,255))
        return fail("PASSWORD");
    if(!ipv4(c.bindAddress)) return fail("BIND");
    if(!c.allowIp.empty()&&!ipv4(c.allowIp)) return fail("IP");
    if(c.maxConnections<1||c.maxConnections>10000) return fail("LIMIT");
    if(c.connectTimeoutSeconds<1||c.connectTimeoutSeconds>300) return fail("TIMEOUT_CONNECT");
    if(c.idleTimeoutSeconds<1||c.idleTimeoutSeconds>86400) return fail("TIMEOUT_HTTP");
    std::set<unsigned> ports;
    auto port=[&](bool enabled,unsigned value)->bool {return !enabled||(value&&ports.insert(value).second);};
    if(!port(c.enableSocks,c.socksPort)||!port(c.enableHttp,c.httpPort)||
       !port(c.enableChainSocks,c.chainSocksPort)||!port(c.enableChainHttp,c.chainHttpPort)||
       !port(c.enableHttps,c.httpsPort)||!port(c.enableSocksTls,c.socksTlsPort)||!port(c.enableDns,c.dnsPort))
        return fail("PORTS");
    if(c.enableSocksUdp&&(!c.udpPortMin||c.udpPortMax<c.udpPortMin))
        return fail("UDP_RANGE");
    if(c.enableSocksUdp&&c.enableDns&&c.dnsPort>=c.udpPortMin&&c.dnsPort<=c.udpPortMax)
        return fail("UDP_DNS_CONFLICT");
    if((c.enableHttps||c.enableSocksTls)&&(!cleanPath(c.tlsCertFile)||!cleanPath(c.tlsKeyFile)))
        return fail("TLS");
    if(!dnsUri(c.dnsServer))
        return fail("DNS");
    if(c.enableDns&&c.dnsServer.empty()) return fail("DNS_REQUIRED");
    if(chainEnabled(c)) {
        if(c.upstreamType!="socks5"&&c.upstreamType!="http") return fail("UPSTREAM");
        if(!dnsHost(c.upstreamHost)||!c.upstreamPort) return fail("UPSTREAM");
        if(c.upstreamUser.empty()!=c.upstreamPassword.empty()) return fail("UPSTREAM_AUTH");
        if(!c.upstreamUser.empty()&&(!printable(c.upstreamUser,1,255)||c.upstreamUser.find(':')!=std::string::npos||!printable(c.upstreamPassword,1,255)))
            return fail("UPSTREAM_AUTH_FORMAT");
        if((c.upstreamHost=="127.0.0.1"||c.upstreamHost=="localhost"||c.upstreamHost==c.bindAddress)&&ports.count(c.upstreamPort))
            return fail("UPSTREAM_LOOP");
    }
    return true;
}

std::string buildGostConfig(const Config& c,unsigned short metricsPort,const std::string& metricsPassword) {
    std::vector<std::string> services;
    if(c.enableSocks) services.push_back(service(c,"direct-socks","socks5",c.socksPort,false,false));
    if(c.enableHttp) services.push_back(service(c,"direct-http","http",c.httpPort,false,false));
    if(c.enableChainSocks) services.push_back(service(c,"chain-socks","socks5",c.chainSocksPort,false,true));
    if(c.enableChainHttp) services.push_back(service(c,"chain-http","http",c.chainHttpPort,false,true));
    if(c.enableHttps) services.push_back(service(c,"tls-http","http",c.httpsPort,true,c.tlsUseChain));
    if(c.enableSocksTls) services.push_back(service(c,"tls-socks","socks5",c.socksTlsPort,true,c.tlsUseChain));
    if(c.enableDns) for(const char* mode:{"udp","tcp"}) {
        services.push_back("{\"name\":"+quote(std::string("dns-")+mode)+",\"addr\":"+address("127.0.0.1",c.dnsPort)+
            ",\"handler\":{\"type\":\"dns\",\"metadata\":{\"dns\":"+quote(c.dnsServer)+
            ",\"timeout\":"+seconds(c.connectTimeoutSeconds)+",\"readTimeout\":\"15s\",\"bufferSize\":\"65535\"}},"
            "\"listener\":{\"type\":\"dns\",\"metadata\":{\"mode\":"+quote(mode)+",\"readTimeout\":\"15s\",\"writeTimeout\":\"15s\"}}}");
    }
    std::string out="{\"services\":[";
    for(std::size_t i=0;i<services.size();++i) {if(i)out+=',';out+=services[i];}
    out+="],\"log\":{\"level\":\"warn\",\"format\":\"json\",\"output\":\"stderr\"}";
    out+=",\"climiters\":[{\"name\":\"connections\",\"limits\":["+quote("$ "+num(c.maxConnections))+"]}]";
    if(metricsPort) out+=",\"metrics\":{\"addr\":"+address("127.0.0.1",metricsPort)+",\"path\":\"/metrics\",\"auth\":"+auth("metrics",metricsPassword)+"}";
    if(!c.allowIp.empty()) out+=",\"admissions\":[{\"name\":\"clients\",\"whitelist\":true,\"matchers\":["+quote(c.allowIp)+"]}]";
    if(!c.dnsServer.empty()) out+=",\"resolvers\":[{\"name\":\"dns-upstream\",\"nameservers\":[{\"addr\":"+quote(c.dnsServer)+",\"timeout\":"+seconds(c.connectTimeoutSeconds)+"}]}]";
    if(c.enableHttps||c.enableSocksTls) out+=",\"tls\":"+tls(c);
    if(chainEnabled(c)) {
        out+=",\"chains\":[{\"name\":\"upstream\",\"hops\":[{\"name\":\"paid-proxy\"";
        if(!c.dnsServer.empty()) out+=",\"resolver\":\"dns-upstream\"";
        out+=",\"nodes\":[{\"name\":\"upstream-node\",\"addr\":"+address(c.upstreamHost,c.upstreamPort)+
             ",\"connector\":{\"type\":"+quote(c.upstreamType);
        if(!c.upstreamUser.empty()) out+=",\"auth\":"+auth(c.upstreamUser,c.upstreamPassword);
        out+=",\"metadata\":{\"timeout\":"+seconds(c.connectTimeoutSeconds);
        if(c.upstreamType=="socks5") out+=",\"notls\":true,\"relay\":\"udp\",\"udp.bufferSize\":\"65535\"";
        out+="}},\"dialer\":{\"type\":\"tcp\"}}]}]}]";
    }
    return out+"}";
}
}
