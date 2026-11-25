#include "service_codec.h"
#include <algorithm>

namespace service_host { namespace codec {
namespace {
const std::uint32_t ProfileMagic=0x31504653;
const std::uint32_t StateMagic=0x31545353;
const std::size_t MaxText=32768;
void eraseText(std::string& value) {
    volatile char* p=value.empty()?nullptr:&value[0];
    for(std::size_t i=0;i<value.size();++i)p[i]=0;
    value.clear();
}
#define CONFIG_FIELDS(X) \
 X(u16,socksPort) X(u16,httpPort) X(text,user) X(text,password) X(text,allowIp) \
 X(boolean,enableSocks) X(boolean,enableHttp) X(boolean,enableSocksUdp) \
 X(u16,udpPortMin) X(u16,udpPortMax) X(boolean,enableHttps) X(u16,httpsPort) \
 X(boolean,enableSocksTls) X(u16,socksTlsPort) X(text,tlsCertFile) X(text,tlsKeyFile) \
 X(text,dnsServer) X(boolean,enableDns) X(u16,dnsPort) X(boolean,tlsUseChain) \
 X(boolean,enableChainSocks) X(boolean,enableChainHttp) X(u16,chainSocksPort) X(u16,chainHttpPort) \
 X(text,upstreamType) X(text,upstreamHost) X(u16,upstreamPort) X(text,upstreamUser) \
 X(text,upstreamPassword) X(text,bindAddress) X(u32,maxConnections) X(u32,idleTimeoutSeconds) X(u32,connectTimeoutSeconds)
#define MT_FIELDS(X) X(u16,listenPort) X(text,bindAddress) X(text,secret) X(text,publicHost)
#define STATS_FIELDS(X) \
 X(u64,active) X(u64,accepted) X(u64,rejected) X(u64,authFailed) X(u64,socks) X(u64,http) \
 X(u64,sent) X(u64,received) X(u64,connectFailed) X(u64,connected) X(u64,authChallenges) \
 X(u64,uptimeSeconds) X(u64,chainSocks) X(u64,chainHttp) X(u64,chainConnected) X(u64,upstreamFailed) \
 X(boolean,metricsAvailable) X(u64,readyServices) X(u64,expectedServices) X(u64,failedServices) X(u64,handlerErrors)
void writeConfig(Writer& w,const proxy::Config& c) {
#define FIELD(type,name) w.type(c.name);
    CONFIG_FIELDS(FIELD)
#undef FIELD
}
void readConfig(Reader& r,proxy::Config& c) {
#define FIELD(type,name) r.type(c.name);
    CONFIG_FIELDS(FIELD)
#undef FIELD
}
void writeMt(Writer& w,const mtproto::Config& c) {
#define FIELD(type,name) w.type(c.name);
    MT_FIELDS(FIELD)
#undef FIELD
}
void readMt(Reader& r,mtproto::Config& c) {
#define FIELD(type,name) r.type(c.name);
    MT_FIELDS(FIELD)
#undef FIELD
}
void writeStats(Writer& w,const proxy::Stats& c) {
#define FIELD(type,name) w.type(c.name);
    STATS_FIELDS(FIELD)
#undef FIELD
}
void readStats(Reader& r,proxy::Stats& c) {
#define FIELD(type,name) r.type(c.name);
    STATS_FIELDS(FIELD)
#undef FIELD
}
}
void Writer::u8(unsigned value) {
    if(!ok||data.size()>=MaxPayload){ok=false;return;}
    data.push_back(static_cast<unsigned char>(value));
}
void Writer::u16(unsigned value){u8(value);u8(value>>8);}
void Writer::u32(std::uint32_t value){for(unsigned i=0;i<4;++i)u8(static_cast<unsigned>(value>>(i*8)));}
void Writer::u64(std::uint64_t value){for(unsigned i=0;i<8;++i)u8(static_cast<unsigned>(value>>(i*8)));}
void Writer::boolean(bool value){u8(value?1:0);}
void Writer::text(const std::string& value) {
    if(value.size()>MaxText||value.find('\0')!=std::string::npos){ok=false;return;}
    u32(static_cast<std::uint32_t>(value.size()));
    if(!ok||value.size()>MaxPayload-data.size()){ok=false;return;}
    data.insert(data.end(),value.begin(),value.end());
}
void Writer::bytes(const Bytes& value) {
    if(value.size()>MaxPayload){ok=false;return;}
    u32(static_cast<std::uint32_t>(value.size()));
    if(!ok||value.size()>MaxPayload-data.size()){ok=false;return;}
    data.insert(data.end(),value.begin(),value.end());
}
Reader::Reader(const Bytes& input):data(input),ok(input.size()<=MaxPayload){}
bool Reader::u8(unsigned& value) {
    if(!ok||position>=data.size()){ok=false;return false;}
    value=data[position++];return true;
}
bool Reader::u16(unsigned short& value) {
    unsigned a=0,b=0;if(!u8(a)||!u8(b))return false;
    value=static_cast<unsigned short>(a|(b<<8));return true;
}
bool Reader::u32(std::uint32_t& value) {
    std::uint32_t out=0;for(unsigned i=0;i<4;++i){unsigned b=0;if(!u8(b))return false;out|=static_cast<std::uint32_t>(b)<<(i*8);}value=out;return true;
}
bool Reader::u64(std::uint64_t& value) {
    std::uint64_t out=0;for(unsigned i=0;i<8;++i){unsigned b=0;if(!u8(b))return false;out|=static_cast<std::uint64_t>(b)<<(i*8);}value=out;return true;
}
bool Reader::boolean(bool& value) {
    unsigned n=0;if(!u8(n)||n>1){ok=false;return false;}value=n!=0;return true;
}
bool Reader::text(std::string& value) {
    std::uint32_t size=0;if(!u32(size)||size>MaxText||size>data.size()-position){ok=false;return false;}
    if(std::find(data.begin()+position,data.begin()+position+size,0)!=data.begin()+position+size){ok=false;return false;}
    value.assign(data.begin()+position,data.begin()+position+size);position+=size;return true;
}
bool Reader::bytes(Bytes& value) {
    std::uint32_t size=0;if(!u32(size)||size>data.size()-position){ok=false;return false;}
    value.assign(data.begin()+position,data.begin()+position+size);position+=size;return true;
}
bool Reader::done() const{return ok&&position==data.size();}
bool encodeProfile(const Profile& p,Bytes& output) {
    Writer w;w.u32(ProfileMagic);w.u32(Version);writeConfig(w,p.proxy);writeMt(w,p.mt);
    w.boolean(p.proxyAutoStart);w.boolean(p.mtAutoStart);w.boolean(p.manageFirewall);w.text(p.tlsDomain);
    if(!w.ok){erase(w.data);return false;}output.swap(w.data);erase(w.data);return true;
}
bool decodeProfile(const Bytes& input,Profile& profile) {
    Reader r(input);std::uint32_t magic=0,version=0;Profile p;
    if(!r.u32(magic)||!r.u32(version)||magic!=ProfileMagic||version!=Version)return false;
    readConfig(r,p.proxy);readMt(r,p.mt);r.boolean(p.proxyAutoStart);r.boolean(p.mtAutoStart);r.boolean(p.manageFirewall);r.text(p.tlsDomain);
    if(!r.done()){erase(p);return false;}erase(profile);profile=std::move(p);return true;
}
bool encodeState(const State& s,Bytes& output) {
    if(s.events.size()>200)return false;
    Writer w;w.u32(StateMagic);w.u32(Version);w.boolean(s.installed);w.boolean(s.reachable);w.u32(s.scmState);
    w.boolean(s.proxyRunning);w.boolean(s.mtRunning);writeStats(w,s.stats);
    w.text(s.proxyError);w.text(s.mtError);w.text(s.error);w.u64(s.proxyRestarts);w.u64(s.mtRestarts);
    w.u32(static_cast<std::uint32_t>(s.events.size()));
    for(const auto& e:s.events){w.u64(e.id);w.text(e.time);w.text(e.level);w.text(e.message);}
    if(!w.ok)return false;
    output.swap(w.data);return true;
}
bool decodeState(const Bytes& input,State& state) {
    Reader r(input);std::uint32_t magic=0,version=0,count=0;State s;
    if(!r.u32(magic)||!r.u32(version)||magic!=StateMagic||version!=Version)return false;
    r.boolean(s.installed);r.boolean(s.reachable);r.u32(s.scmState);r.boolean(s.proxyRunning);r.boolean(s.mtRunning);readStats(r,s.stats);
    r.text(s.proxyError);r.text(s.mtError);r.text(s.error);r.u64(s.proxyRestarts);r.u64(s.mtRestarts);
    if(!r.u32(count)||count>200)return false;
    for(std::uint32_t i=0;i<count&&r.ok;++i){proxy::Event e;r.u64(e.id);r.text(e.time);r.text(e.level);r.text(e.message);s.events.push_back(e);}
    if(!r.done())return false;
    state=std::move(s);return true;
}
void erase(Bytes& value) {volatile unsigned char* p=value.empty()?nullptr:value.data();for(std::size_t i=0;i<value.size();++i)p[i]=0;value.clear();}
void erase(Profile& profile) {eraseText(profile.proxy.password);eraseText(profile.proxy.upstreamPassword);eraseText(profile.mt.secret);}
} }
