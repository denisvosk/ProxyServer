// Portable tests for the bounded service wire/profile format. No Windows
// service, real profile, network, filesystem or firewall is touched here.
#include "service_codec.h"
#include <iostream>
#include <limits>
#include <stdexcept>

using namespace service_host;
using codec::Bytes;
static unsigned checks=0;
static void require(bool value,const char* message){++checks;if(!value)throw std::runtime_error(message);}
static Profile sample() {
    Profile p;auto& c=p.proxy;
    c.socksPort=11080;c.httpPort=18080;c.user="codec-user";c.password="codec-only-secret";c.allowIp="192.0.2.3";
    c.enableSocks=false;c.enableHttp=false;c.enableSocksUdp=false;c.udpPortMin=23400;c.udpPortMax=23419;
    c.enableHttps=true;c.httpsPort=18443;c.enableSocksTls=true;c.socksTlsPort=11443;
    c.tlsCertFile="C:\\protected\\cert.pem";c.tlsKeyFile="C:\\protected\\key.pem";
    c.dnsServer="https://resolver.example/dns-query";c.enableDns=true;c.dnsPort=11053;c.tlsUseChain=true;
    c.enableChainSocks=true;c.enableChainHttp=true;c.chainSocksPort=11081;c.chainHttpPort=18081;
    c.upstreamType="http";c.upstreamHost="proxy.example";c.upstreamPort=3128;c.upstreamUser="provider-user";c.upstreamPassword="provider-only-secret";
    c.bindAddress="127.0.0.2";c.maxConnections=777;c.idleTimeoutSeconds=480;c.connectTimeoutSeconds=23;
    p.mt.listenPort=19443;p.mt.bindAddress="192.0.2.5";p.mt.secret="ee0123456789abcdef0123456789abcdef6578616d706c652e636f6d";p.mt.publicHost="public.example";
    p.proxyAutoStart=true;p.mtAutoStart=true;p.manageFirewall=false;p.tlsDomain="example.com";return p;
}
static void equalProfile(const Profile& a,const Profile& b) {
#define CHECK(name) require(a.proxy.name==b.proxy.name,"profile field lost: " #name)
    CHECK(socksPort);CHECK(httpPort);CHECK(user);CHECK(password);CHECK(allowIp);CHECK(enableSocks);CHECK(enableHttp);CHECK(enableSocksUdp);
    CHECK(udpPortMin);CHECK(udpPortMax);CHECK(enableHttps);CHECK(httpsPort);CHECK(enableSocksTls);CHECK(socksTlsPort);CHECK(tlsCertFile);CHECK(tlsKeyFile);
    CHECK(dnsServer);CHECK(enableDns);CHECK(dnsPort);CHECK(tlsUseChain);CHECK(enableChainSocks);CHECK(enableChainHttp);CHECK(chainSocksPort);CHECK(chainHttpPort);
    CHECK(upstreamType);CHECK(upstreamHost);CHECK(upstreamPort);CHECK(upstreamUser);CHECK(upstreamPassword);CHECK(bindAddress);CHECK(maxConnections);CHECK(idleTimeoutSeconds);CHECK(connectTimeoutSeconds);
#undef CHECK
    require(a.mt.listenPort==b.mt.listenPort&&a.mt.bindAddress==b.mt.bindAddress&&a.mt.secret==b.mt.secret&&a.mt.publicHost==b.mt.publicHost,"Telegram fields lost");
    require(a.proxyAutoStart==b.proxyAutoStart&&a.mtAutoStart==b.mtAutoStart&&a.manageFirewall==b.manageFirewall&&a.tlsDomain==b.tlsDomain,"profile policy fields lost");
}
int main() {
    try {
        Profile source=sample(),decoded;Bytes encoded;
        require(codec::encodeProfile(source,encoded),"profile encode failed");
        require(codec::decodeProfile(encoded,decoded),"profile decode failed");equalProfile(source,decoded);
        Profile defaults;Bytes defaultBytes;require(codec::encodeProfile(defaults,defaultBytes),"default profile encode failed");
        require(codec::decodeProfile(defaultBytes,decoded),"inactive blank profile rejected");equalProfile(defaults,decoded);
        for(std::size_t n=0;n<encoded.size();++n) {
            Bytes truncated(encoded.begin(),encoded.begin()+n);Profile unchanged=source;
            require(!codec::decodeProfile(truncated,unchanged),"truncated profile accepted");
            require(unchanged.proxy.password==source.proxy.password&&unchanged.mt.secret==source.mt.secret,"failed decode modified existing credentials");
        }
        Bytes bad=encoded;bad[0]^=1;require(!codec::decodeProfile(bad,decoded),"unknown profile magic accepted");
        bad=encoded;bad[4]=2;require(!codec::decodeProfile(bad,decoded),"unknown profile version accepted");
        bad=encoded;bad.push_back(0);require(!codec::decodeProfile(bad,decoded),"profile trailing bytes accepted");
        bad=defaultBytes;bad[bad.size()-7]=2;require(!codec::decodeProfile(bad,decoded),"invalid boolean accepted");
        bad=encoded;for(unsigned i=12;i<16;++i)bad[i]=255;require(!codec::decodeProfile(bad,decoded),"oversized string length accepted");
        Profile invalid=source;invalid.proxy.password=std::string("has\0nul",7);require(!codec::encodeProfile(invalid,bad),"embedded NUL encoded");
        invalid=source;invalid.proxy.tlsKeyFile.assign(32769,'x');require(!codec::encodeProfile(invalid,bad),"oversized string encoded");
        bad.assign(codec::MaxPayload+1,0);require(!codec::decodeProfile(bad,decoded),"oversized profile decoded");

        State state;state.installed=true;state.reachable=true;state.scmState=4;state.proxyRunning=true;state.mtRunning=true;
        state.proxyError="sanitized proxy error";state.mtError="sanitized MT error";state.error="sanitized profile error";
        state.proxyRestarts=17;state.mtRestarts=19;
        auto& s=state.stats;
        s.active=1;s.accepted=2;s.rejected=3;s.authFailed=4;s.socks=5;s.http=6;s.sent=7;s.received=8;s.connectFailed=9;
        s.connected=10;s.authChallenges=11;s.uptimeSeconds=12;s.chainSocks=13;s.chainHttp=14;s.chainConnected=15;s.upstreamFailed=16;
        s.metricsAvailable=true;s.readyServices=18;s.expectedServices=19;s.failedServices=20;s.handlerErrors=(std::numeric_limits<std::uint64_t>::max)();
        for(unsigned i=0;i<200;++i){proxy::Event event;event.id=100000+i;event.time="12:34:56";event.level="warning";event.message.assign(1024,'x');state.events.push_back(event);}
        Bytes wire;State restored;
        require(codec::encodeState(state,wire),"bounded full event window cannot be encoded");
        require(codec::decodeState(wire,restored),"state decode failed");
        require(restored.installed&&restored.reachable&&restored.scmState==4&&restored.proxyRunning&&restored.mtRunning,"state flags lost");
        require(restored.proxyError==state.proxyError&&restored.mtError==state.mtError&&restored.error==state.error,"state diagnostics lost");
        require(restored.proxyRestarts==17&&restored.mtRestarts==19,"restart counters lost");
#define CHECK(name) require(restored.stats.name==s.name,"statistics field lost: " #name)
        CHECK(active);CHECK(accepted);CHECK(rejected);CHECK(authFailed);CHECK(socks);CHECK(http);CHECK(sent);CHECK(received);CHECK(connectFailed);
        CHECK(connected);CHECK(authChallenges);CHECK(uptimeSeconds);CHECK(chainSocks);CHECK(chainHttp);CHECK(chainConnected);CHECK(upstreamFailed);
        CHECK(metricsAvailable);CHECK(readyServices);CHECK(expectedServices);CHECK(failedServices);CHECK(handlerErrors);
#undef CHECK
        require(restored.events.size()==200&&restored.events.front().id==100000&&restored.events.back().id==100199,"event order or identifiers lost");
        require(restored.events.back().message==state.events.back().message,"event content lost");
        state.events.push_back(proxy::Event());require(!codec::encodeState(state,bad),"unbounded event count accepted");state.events.pop_back();
        state.events.front().message.assign(32768,'x');state.events[1].message.assign(32768,'y');require(!codec::encodeState(state,bad),"oversized total state accepted");
        for(std::size_t n=0;n<wire.size();n+=997) {Bytes truncated(wire.begin(),wire.begin()+n);require(!codec::decodeState(truncated,restored),"truncated state accepted");}
        bad=wire;bad.push_back(1);require(!codec::decodeState(bad,restored),"state trailing bytes accepted");
        bad=wire;bad[4]=99;require(!codec::decodeState(bad,restored),"unknown state version accepted");
        codec::Writer writer;writer.boolean(true);writer.text("bounded");writer.bytes(Bytes(16,7));codec::Reader reader(writer.data);
        bool boolean=false;std::string text;Bytes body;
        require(reader.boolean(boolean)&&boolean&&reader.text(text)&&text=="bounded"&&reader.bytes(body)&&body==Bytes(16,7)&&reader.done(),"response envelope round trip failed");
        codec::erase(encoded);require(encoded.empty(),"byte buffer erase did not clear length");codec::erase(source);
        require(source.proxy.password.empty()&&source.proxy.upstreamPassword.empty()&&source.mt.secret.empty(),"profile secret erase failed");
        std::cout<<"PASS service codec: "<<checks<<" assertions; bounded round trips, malformed input and secret clearing\n";
        return 0;
    } catch(const std::exception& error){std::cerr<<"FAIL service codec: "<<error.what()<<"\n";return 1;}
}
