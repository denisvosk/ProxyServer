// Local test utility. Prints a configuration containing TEST credentials only.
#include "gost_config.h"
#include <cstdlib>
#include <iostream>
#include <stdexcept>

int main(int argc,char** argv) {
    proxy::Config c;
    c.bindAddress="127.0.0.1";
    c.user="testuser";c.password="test-only-123!";
    unsigned short metrics=0;
    try {
        for(int i=1;i<argc;++i) {
            std::string a=argv[i];const auto eq=a.find('=');
            if(eq==std::string::npos) throw std::runtime_error("expected key=value");
            std::string k=a.substr(0,eq),v=a.substr(eq+1);
            const bool b=v=="1"||v=="true";
            auto number=[&]()->unsigned {const unsigned long n=std::stoul(v);if(n>65535)throw std::runtime_error("number out of range");return static_cast<unsigned>(n);};
            if(k=="socks")c.socksPort=static_cast<unsigned short>(number());
            else if(k=="http")c.httpPort=static_cast<unsigned short>(number());
            else if(k=="metrics")metrics=static_cast<unsigned short>(number());
            else if(k=="enable-socks")c.enableSocks=b;
            else if(k=="enable-http")c.enableHttp=b;
            else if(k=="udp")c.enableSocksUdp=b;
            else if(k=="udp-min")c.udpPortMin=static_cast<unsigned short>(number());
            else if(k=="udp-max")c.udpPortMax=static_cast<unsigned short>(number());
            else if(k=="https"){c.enableHttps=true;c.httpsPort=static_cast<unsigned short>(number());}
            else if(k=="socks-tls"){c.enableSocksTls=true;c.socksTlsPort=static_cast<unsigned short>(number());}
            else if(k=="tls-chain")c.tlsUseChain=b;
            else if(k=="cert")c.tlsCertFile=v;
            else if(k=="key")c.tlsKeyFile=v;
            else if(k=="dns")c.dnsServer=v;
            else if(k=="dns-port"){c.enableDns=true;c.dnsPort=static_cast<unsigned short>(number());}
            else if(k=="chain-socks"){c.enableChainSocks=true;c.chainSocksPort=static_cast<unsigned short>(number());}
            else if(k=="chain-http"){c.enableChainHttp=true;c.chainHttpPort=static_cast<unsigned short>(number());}
            else if(k=="up-type")c.upstreamType=v;
            else if(k=="up-host")c.upstreamHost=v;
            else if(k=="up-port")c.upstreamPort=static_cast<unsigned short>(number());
            else if(k=="up-user")c.upstreamUser=v;
            else if(k=="up-pass")c.upstreamPassword=v;
            else if(k=="bind")c.bindAddress=v;
            else if(k=="allow")c.allowIp=v;
            else if(k=="max")c.maxConnections=number();
            else if(k=="timeout")c.connectTimeoutSeconds=number();
            else if(k=="idle")c.idleTimeoutSeconds=number();
            else if(k=="user")c.user=v;
            else if(k=="password")c.password=v;
            else throw std::runtime_error("unknown option: "+k);
        }
        std::string error;
        if(!proxy::validate(c,error)){std::cerr<<error<<'\n';return 2;}
        std::cout<<proxy::buildGostConfig(c,metrics,"test-metrics-secret")<<std::endl;
        return 0;
    } catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 2;}
}
