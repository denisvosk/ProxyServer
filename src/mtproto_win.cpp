#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <string>
#include <vector>
#include "mtproto_win.h"
#ifdef _MSC_VER
#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"ws2_32.lib")
#endif

namespace mtproto {
namespace {
int hexValue(char ch) {
    if(ch>='0'&&ch<='9') return ch-'0';
    if(ch>='a'&&ch<='f') return ch-'a'+10;
    if(ch>='A'&&ch<='F') return ch-'A'+10;
    return -1;
}
bool hostname(const std::string& host) {
    if(host.empty()||host.size()>253||host.front()=='.'||host.back()=='.') return false;
    std::size_t begin=0;
    for(std::size_t i=0;i<=host.size();++i) {
        if(i==host.size()||host[i]=='.') {
            const std::size_t length=i-begin;
            if(!length||length>63||host[begin]=='-'||host[i-1]=='-') return false;
            begin=i+1;
        } else {
            const unsigned char c=static_cast<unsigned char>(host[i]);
            if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-')) return false;
        }
    }
    return true;
}
std::string lower(std::string value) {
    for(char& c:value) if(c>='A'&&c<='Z') c=static_cast<char>(c-'A'+'a');
    return value;
}
std::string encoded(const std::string& value) {
    static const char hex[]="0123456789ABCDEF";
    std::string result;
    for(unsigned char c:value) {
        if((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'||c=='~')
            result+=static_cast<char>(c);
        else { result+='%'; result+=hex[c>>4]; result+=hex[c&15]; }
    }
    return result;
}
}
bool secretDomain(const std::string& secret,std::string& domain) {
    domain.clear();
    if(secret.size()<36||secret.size()>34+253*2||secret.size()%2 ||
       (secret[0]!='e'&&secret[0]!='E')||(secret[1]!='e'&&secret[1]!='E')) return false;
    unsigned nonzero=0;
    for(std::size_t i=2;i<secret.size();i+=2) {
        int a=hexValue(secret[i]),b=hexValue(secret[i+1]);
        if(a<0||b<0) { domain.clear(); return false; }
        const unsigned char value=static_cast<unsigned char>((a<<4)|b);
        if(i<34) nonzero|=value;
        else domain+=static_cast<char>(value);
    }
    if(!nonzero || !hostname(domain)) { domain.clear(); return false; }
    return true;
}
bool validate(const Config& config,std::string& error) {
    error.clear();
    in_addr ip4={};
    if(!config.listenPort) { error="MT_PORT"; return false; }
    if(inet_pton(AF_INET,config.bindAddress.c_str(),&ip4)!=1) { error="MT_BIND"; return false; }
    std::string domain;
    if(!secretDomain(config.secret,domain)) { error="MT_SECRET"; return false; }
    if(!config.publicHost.empty()) {
        in6_addr ip6={};
        if(inet_pton(AF_INET,config.publicHost.c_str(),&ip4)!=1 &&
           inet_pton(AF_INET6,config.publicHost.c_str(),&ip6)!=1 && !hostname(config.publicHost)) {
            error="MT_PUBLIC_HOST"; return false;
        }
    }
    return true;
}
bool generateSecret(const std::string& domain,std::string& secret,std::string& error) {
    error.clear();
    const std::string host=lower(domain);
    if(!hostname(host)) { error="MT_DOMAIN"; return false; }
    unsigned char random[16]={};
    const NTSTATUS status=BCryptGenRandom(nullptr,random,sizeof(random),BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if(status<0) { SecureZeroMemory(random,sizeof(random)); error=u8"Windows не смогла создать криптографически случайный секрет."; return false; }
    unsigned nonzero=0;
    for(unsigned char value:random) nonzero|=value;
    if(!nonzero) { SecureZeroMemory(random,sizeof(random)); error=u8"Генератор случайных чисел вернул недопустимый ключ. Повторите создание секрета."; return false; }
    static const char hex[]="0123456789abcdef";
    std::string generated="ee";
    generated.reserve(34+host.size()*2);
    for(unsigned char value:random) { generated+=hex[value>>4]; generated+=hex[value&15]; }
    for(unsigned char value:host) { generated+=hex[value>>4]; generated+=hex[value&15]; }
    SecureZeroMemory(random,sizeof(random));
    secret.swap(generated);
    if(!generated.empty()) SecureZeroMemory(&generated[0],generated.size());
    return true;
}
std::string buildTelegramLink(const Config& config) {
    std::string error;
    if(config.publicHost.empty()||!validate(config,error)) return "";
    return "https://t.me/proxy?server="+encoded(config.publicHost)+
        "&port="+std::to_string(config.listenPort)+"&secret="+encoded(lower(config.secret));
}
bool Controller::start(const std::wstring& absoluteExePath,const Config& config,std::string& error) {
    error_.clear();
    if(!validate(config,error)) { error_=error; return false; }
    if(process_.running()) { error=u8"Компонент MTProto уже запущен."; error_=error; return false; }
    SOCKET probe=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(probe==INVALID_SOCKET) { error=u8"Не удалось проверить порт MTProto."; error_=error; return false; }
    BOOL exclusive=TRUE;
    sockaddr_in endpoint={}; endpoint.sin_family=AF_INET;
    endpoint.sin_port=htons(config.listenPort);
    inet_pton(AF_INET,config.bindAddress.c_str(),&endpoint.sin_addr);
    const bool available=setsockopt(probe,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof(exclusive))==0 &&
                         bind(probe,reinterpret_cast<sockaddr*>(&endpoint),sizeof(endpoint))==0;
    const int socketError=available?0:WSAGetLastError();
    closesocket(probe);
    if(!available) {
        error=u8"MTProto не может занять TCP-порт "+std::to_string(config.listenPort)+u8" (код Winsock "+std::to_string(socketError)+u8"). Проверьте адрес интерфейса и программы, использующие этот порт.";
        error_=error; return false;
    }
    // Only numeric bind values and validated hex enter TOML. No user-supplied
    // configuration syntax, no plaintext configuration file, no CLI secrets.
    std::string toml="debug = false\nsecret = \""+lower(config.secret)+
        "\"\nbind-to = \""+config.bindAddress+":"+std::to_string(config.listenPort)+
        "\"\nconcurrency = 256\nprefer-ip = \"prefer-ipv4\"\nauto-update = false\n"
        "[network.timeout]\ntcp = \"15s\"\nhttp = \"15s\"\nidle = \"30m\"\nhandshake = \"20s\"\n"
        "[defense.anti-replay]\nenabled = true\nmax-size = \"1mib\"\n"
        "[defense.blocklist]\nenabled = false\n"
        "[defense.allowlist]\nenabled = false\n"
        "[stats.prometheus]\nenabled = false\n"
        "[stats.statsd]\nenabled = false\n";
    const std::vector<std::wstring> arguments={L"run",L"--skip-startup-checks",L"-"};
    const bool started=process_.start(absoluteExePath,arguments,toml,error);
    if(!toml.empty()) SecureZeroMemory(&toml[0],toml.size());
    if(!started) error_=error;
    return started;
}
void Controller::stop() { process_.stop(); }
void Controller::poll() { process_.poll(); }
bool Controller::running() const { return process_.running(); }
std::string Controller::lastError() const {
    if(!error_.empty()) return error_;
    return process_.lastError();
}
}
