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
#include <winhttp.h>
#include <bcrypt.h>
#include "proxy_core.h"
#include "gost_config.h"
#include "child_process_win.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <ctime>
#include <deque>
#include <limits>
#include <locale>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>
#ifdef _MSC_VER
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"winhttp.lib")
#pragma comment(lib,"bcrypt.lib")
#endif

namespace proxy {
namespace {
std::wstring utf16(const std::string& value) {
    if(value.empty()) return L"";
    int size=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0);
    if(size<=0) return L"";
    std::wstring result(static_cast<std::size_t>(size),L'\0');
    if(!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),&result[0],size)) return L"";
    return result;
}
std::wstring enginePath() {
    std::vector<wchar_t> path(32768);
    DWORD count=GetModuleFileNameW(nullptr,path.data(),static_cast<DWORD>(path.size()));
    if(!count||count>=path.size()) return L"";
    std::wstring result(path.data(),count);
    auto slash=result.find_last_of(L"\\/");
    if(slash==std::wstring::npos) return L"";
    return result.substr(0,slash+1)+L"components\\gost.exe";
}
bool regularFile(const std::string& path) {
    const std::wstring wide=utf16(path);
    if(wide.empty()) return false;
    DWORD attr=GetFileAttributesW(wide.c_str());
    return attr!=INVALID_FILE_ATTRIBUTES && !(attr&FILE_ATTRIBUTE_DIRECTORY);
}
struct SocketHolder {
    SOCKET value=INVALID_SOCKET;
    explicit SocketHolder(SOCKET socket=INVALID_SOCKET):value(socket) {}
    ~SocketHolder(){if(value!=INVALID_SOCKET) closesocket(value);}
    SocketHolder(SocketHolder&& other) noexcept:value(other.value){other.value=INVALID_SOCKET;}
    SocketHolder(const SocketHolder&)=delete;
    SocketHolder& operator=(const SocketHolder&)=delete;
};
bool reservePort(std::vector<SocketHolder>& sockets,const std::string& address,
                 unsigned short port,bool udp,unsigned short* assigned,std::string& error) {
    SocketHolder socket(::socket(AF_INET,udp?SOCK_DGRAM:SOCK_STREAM,udp?IPPROTO_UDP:IPPROTO_TCP));
    BOOL exclusive=TRUE;
    sockaddr_in bindAddress={}; bindAddress.sin_family=AF_INET; bindAddress.sin_port=htons(port);
    if(inet_pton(AF_INET,address.c_str(),&bindAddress.sin_addr)!=1) {error=u8"Некорректный адрес сетевого интерфейса.";return false;}
    if(socket.value==INVALID_SOCKET ||
       setsockopt(socket.value,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof(exclusive))!=0 ||
       bind(socket.value,reinterpret_cast<sockaddr*>(&bindAddress),sizeof(bindAddress))!=0) {
        const int code=WSAGetLastError();
        error=std::string(u8"Не удалось открыть ")+(udp?"UDP ":"TCP ")+address+":"+std::to_string(port)+
              u8" (код Winsock "+std::to_string(code)+u8"). Остановите программу, занимающую порт, или выберите другой порт.";
        return false;
    }
    if(assigned) {
        int length=sizeof(bindAddress);
        if(getsockname(socket.value,reinterpret_cast<sockaddr*>(&bindAddress),&length)!=0) {error=u8"Не удалось зарезервировать локальный порт счётчиков.";return false;}
        *assigned=ntohs(bindAddress.sin_port);
    }
    sockets.push_back(std::move(socket));
    return true;
}
unsigned serviceCount(const Config& c) {
    return (c.enableSocks?1u:0u)+(c.enableHttp?1u:0u)+(c.enableChainSocks?1u:0u)+
           (c.enableChainHttp?1u:0u)+(c.enableSocksTls?1u:0u)+(c.enableHttps?1u:0u)+(c.enableDns?2u:0u);
}
bool preflight(const Config& c,unsigned short& metricsPort,std::string& error) {
    std::vector<SocketHolder> reservations;
    const bool enabled[]={c.enableSocks,c.enableHttp,c.enableChainSocks,c.enableChainHttp,c.enableSocksTls,c.enableHttps};
    const unsigned short ports[]={c.socksPort,c.httpPort,c.chainSocksPort,c.chainHttpPort,c.socksTlsPort,c.httpsPort};
    for(unsigned i=0;i<6;++i)
        if(enabled[i]&&!reservePort(reservations,c.bindAddress,ports[i],false,nullptr,error)) return false;
    if(c.enableDns && (!reservePort(reservations,"127.0.0.1",c.dnsPort,false,nullptr,error) ||
                       !reservePort(reservations,"127.0.0.1",c.dnsPort,true,nullptr,error))) return false;
    if(!reservePort(reservations,"127.0.0.1",0,false,&metricsPort,error)) return false;
    // Reservations end together immediately before creating the engine process.
    // The engine still remains responsible for its actual bind result.
    return true;
}
std::string base64(const std::string& input) {
    static const char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    for(std::size_t i=0;i<input.size();i+=3) {
        unsigned a=static_cast<unsigned char>(input[i]);
        unsigned b=i+1<input.size()?static_cast<unsigned char>(input[i+1]):0;
        unsigned c=i+2<input.size()?static_cast<unsigned char>(input[i+2]):0;
        result+=alphabet[a>>2]; result+=alphabet[((a&3)<<4)|(b>>4)];
        result+=i+1<input.size()?alphabet[((b&15)<<2)|(c>>6)]:'=';
        result+=i+2<input.size()?alphabet[c&63]:'=';
    }
    return result;
}
bool randomPassword(std::string& password) {
    unsigned char bytes[32]={};
    NTSTATUS status=BCryptGenRandom(nullptr,bytes,sizeof(bytes),BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if(status<0) return false;
    static const char hex[]="0123456789abcdef";
    password.clear(); password.reserve(sizeof(bytes)*2);
    for(unsigned char b:bytes){password+=hex[b>>4];password+=hex[b&15];}
    SecureZeroMemory(bytes,sizeof(bytes));
    return true;
}
struct InternetHandle {
    HINTERNET value;
    explicit InternetHandle(HINTERNET handle=nullptr):value(handle){}
    ~InternetHandle(){if(value)WinHttpCloseHandle(value);}
    InternetHandle(const InternetHandle&)=delete;
    InternetHandle& operator=(const InternetHandle&)=delete;
};
struct Monitor {
    unsigned short port=0;
    unsigned expected=0;
    std::wstring authorization;
    std::atomic<bool> stop{false};
    std::mutex mutex;
    Stats snapshot;
    ULONGLONG lastSuccess=0;
    ~Monitor(){if(!authorization.empty())SecureZeroMemory(&authorization[0],authorization.size()*sizeof(wchar_t));}
};
bool readMetrics(Monitor& monitor,std::string& body) {
    if(monitor.stop) return false;
    InternetHandle session(WinHttpOpen(L"ProxyServer/2.0",WINHTTP_ACCESS_TYPE_NO_PROXY,
                                      WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0));
    if(!session.value || !WinHttpSetTimeouts(session.value,250,250,250,250)) return false;
    InternetHandle connection(WinHttpConnect(session.value,L"127.0.0.1",monitor.port,0));
    if(!connection.value || monitor.stop) return false;
    InternetHandle request(WinHttpOpenRequest(connection.value,L"GET",L"/metrics",nullptr,
                                              WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,0));
    if(!request.value) return false;
    DWORD disable=WINHTTP_DISABLE_REDIRECTS|WINHTTP_DISABLE_COOKIES;
    if(!WinHttpSetOption(request.value,WINHTTP_OPTION_DISABLE_FEATURE,&disable,sizeof(disable))) return false;
    if(!WinHttpAddRequestHeaders(request.value,monitor.authorization.c_str(),static_cast<DWORD>(-1L),WINHTTP_ADDREQ_FLAG_ADD)) return false;
    const ULONGLONG deadline=GetTickCount64()+2000;
    if(monitor.stop || !WinHttpSendRequest(request.value,WINHTTP_NO_ADDITIONAL_HEADERS,0,
                                          WINHTTP_NO_REQUEST_DATA,0,0,0) || monitor.stop ||
       !WinHttpReceiveResponse(request.value,nullptr)) return false;
    DWORD status=0,size=sizeof(status);
    if(!WinHttpQueryHeaders(request.value,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX,&status,&size,WINHTTP_NO_HEADER_INDEX) || status!=200) return false;
    body.clear();
    char buffer[8192];
    while(!monitor.stop && GetTickCount64()<deadline) {
        DWORD count=0;
        if(!WinHttpReadData(request.value,buffer,sizeof(buffer),&count)) return false;
        if(!count) return true;
        if(body.size()+count>1024*1024) return false;
        body.append(buffer,count);
    }
    return false;
}
std::uint64_t add(std::uint64_t a,std::uint64_t b) {
    const auto max=(std::numeric_limits<std::uint64_t>::max)();
    return a>max-b?max:a+b;
}
bool metric(const std::string& line,std::string& name,std::string& service,std::string& state,std::uint64_t& number) {
    service.clear(); state.clear();
    if(line.empty()||line[0]=='#') return false;
    std::size_t i=line.find_first_of("{ \t");
    if(i==std::string::npos) return false;
    name=line.substr(0,i);
    if(name.compare(0,5,"gost_")!=0) return false;
    if(line[i]=='{') {
        ++i;
        for(;;) {
            while(i<line.size()&&(line[i]==' '||line[i]=='\t'||line[i]==',')) ++i;
            if(i>=line.size()) return false;
            if(line[i]=='}'){++i;break;}
            auto equals=line.find('=',i);
            if(equals==std::string::npos) return false;
            const std::string label=line.substr(i,equals-i);
            i=equals+1;
            if(i>=line.size()||line[i++]!='"') return false;
            std::string value;
            bool closed=false;
            while(i<line.size()) {
                char c=line[i++];
                if(c=='"'){closed=true;break;}
                if(c=='\\') {
                    if(i>=line.size()) return false;
                    c=line[i++];
                    if(c=='n') c='\n';
                    else if(c!='\\'&&c!='"') return false;
                }
                value+=c;
            }
            if(!closed) return false;
            if(label=="service") service=value;
            else if(label=="state") state=value;
            if(i>=line.size()||(line[i]!=','&&line[i]!='}')) return false;
        }
    }
    std::istringstream input(line.substr(i));
    input.imbue(std::locale::classic());
    long double value=0;
    if(!(input>>value)||!std::isfinite(value)||value<0) return false;
    const long double maximum=static_cast<long double>((std::numeric_limits<std::uint64_t>::max)());
    number=value>=maximum?(std::numeric_limits<std::uint64_t>::max)():static_cast<std::uint64_t>(value);
    return true;
}
bool parseMetrics(const std::string& body,Stats& stats) {
    std::istringstream input(body);
    std::string line,name,service,state;
    bool recognized=false,haveStatus=false;
    std::uint64_t services=0;
    while(std::getline(input,line)) {
        std::uint64_t value=0;
        if(!metric(line,name,service,state,value)) continue;
        if(name=="gost_services") {recognized=true;services=add(services,value);}
        else if(name=="gost_service_status") {
            recognized=true;haveStatus=true;
            if(state=="ready") stats.readyServices=add(stats.readyServices,value);
            else if(state=="failed") stats.failedServices=add(stats.failedServices,value);
        } else if(name=="gost_service_requests_total") {
            stats.accepted=add(stats.accepted,value);
            if(service=="direct-socks"||service=="tls-socks") stats.socks=add(stats.socks,value);
            else if(service=="direct-http"||service=="tls-http") stats.http=add(stats.http,value);
            else if(service=="chain-socks") stats.chainSocks=add(stats.chainSocks,value);
            else if(service=="chain-http") stats.chainHttp=add(stats.chainHttp,value);
        } else if(name=="gost_service_requests_in_flight") stats.active=add(stats.active,value);
        else if(name=="gost_service_transfer_input_bytes_total") stats.sent=add(stats.sent,value);
        else if(name=="gost_service_transfer_output_bytes_total") stats.received=add(stats.received,value);
        else if(name=="gost_service_handler_errors_total") stats.handlerErrors=add(stats.handlerErrors,value);
        else if(name=="gost_chain_errors_total") stats.upstreamFailed=add(stats.upstreamFailed,value);
    }
    // Pinned GOST 3.3.3 exposes gost_services but does not register its optional
    // service-status collector. In that version the service gauge is the only
    // local startup signal; it is not a check of reachability from the Internet.
    if(!haveStatus) stats.readyServices=services;
    stats.metricsAvailable=recognized;
    return recognized;
}
void monitorLoop(std::shared_ptr<Monitor> monitor) {
    while(!monitor->stop) {
        Stats current;
        current.expectedServices=monitor->expected;
        std::string response;
        bool ok=false;
        try {ok=readMetrics(*monitor,response)&&parseMetrics(response,current);} catch(...){ok=false;}
        {
            std::lock_guard<std::mutex> lock(monitor->mutex);
            if(ok) {monitor->snapshot=current;monitor->lastSuccess=GetTickCount64();}
            else monitor->snapshot.metricsAvailable=false;
        }
        for(unsigned i=0;i<10&&!monitor->stop;++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}
}

struct Backend {
    child_process::Process process;
    std::shared_ptr<Monitor> monitor;
    std::thread worker;
    std::deque<Event> log;
    std::uint64_t nextEvent=1;
    ULONGLONG started=0,ended=0,lastWarning=0;
    bool active=false,readyLogged=false,metricsWarning=false;
    unsigned expected=0;
    std::uint64_t lastHandlerErrors=0,lastUpstreamErrors=0,lastFailedServices=0;
    std::string error;

    void event(const std::string& level,const std::string& message) {
        Event value; value.id=nextEvent++;value.level=level;value.message=message;
        std::time_t now=std::time(nullptr); std::tm local={}; localtime_s(&local,&now);
        char time[16]={};std::strftime(time,sizeof(time),"%H:%M:%S",&local);value.time=time;
        log.push_back(value);while(log.size()>200)log.pop_front();
    }
    void stopMonitor() {
        if(monitor) monitor->stop=true;
        if(worker.joinable()) worker.join();
    }
    Stats snapshot() const {
        Stats value;value.expectedServices=expected;
        if(monitor) {std::lock_guard<std::mutex> lock(monitor->mutex);value=monitor->snapshot;value.expectedServices=expected;}
        if(started) value.uptimeSeconds=((active?GetTickCount64():ended)-started)/1000;
        if(!active) {value.active=0;value.metricsAvailable=false;value.readyServices=0;}
        return value;
    }
    void poll() {
        process.poll();
        if(active&&!process.running()) {
            active=false;ended=GetTickCount64();
            stopMonitor();
            error=process.lastError();
            if(error.empty()) error=u8"Ядро GOST неожиданно завершилось.";
            event("error",error);
            return;
        }
        if(!active) return;
        Stats value=snapshot();
        if(value.metricsAvailable && value.readyServices>=expected && expected && !readyLogged) {
            readyLogged=true;event("info",u8"GOST сообщил о запуске всех служб: "+std::to_string(expected)+u8". Доступность сервера из Интернета не проверялась.");
        }
        if(!value.metricsAvailable && GetTickCount64()-started>10000 && !metricsWarning) {
            metricsWarning=true;event("warning",u8"Локальные счётчики GOST недоступны. Работающий процесс ещё не подтверждает готовность портов.");
        }
        if(value.metricsAvailable) metricsWarning=false;
        if(value.failedServices && value.failedServices!=lastFailedServices)
            event("warning",u8"GOST сообщил об ошибке слушателей: "+std::to_string(value.failedServices)+u8". Ядро пытается восстановить их работу.");
        lastFailedServices=value.failedServices;
        if((value.handlerErrors>lastHandlerErrors || value.upstreamFailed>lastUpstreamErrors) && GetTickCount64()-lastWarning>5000) {
            event("warning",u8"Выросли счётчики ошибок GOST: обработка="+std::to_string(value.handlerErrors)+
                            u8", подключение к внешнему прокси="+std::to_string(value.upstreamFailed)+u8". Проверьте настройки клиента и внешнего прокси, а также соединение с сетью.");
            lastWarning=GetTickCount64();
        }
        lastHandlerErrors=value.handlerErrors;lastUpstreamErrors=value.upstreamFailed;
    }
};
bool networkInit(std::string& error) {
    WSADATA data={};int code=WSAStartup(MAKEWORD(2,2),&data);
    if(code){error=u8"Не удалось инициализировать Winsock. Код: "+std::to_string(code);return false;}
    error.clear();return true;
}
void networkCleanup(){WSACleanup();}
Server::Server():backend_(new Backend){}
Server::~Server(){stop();}
bool Server::start(const Config& config,std::string& error) {
    backend_->poll();
    if(backend_->active){error="ALREADY_RUNNING";return false;}
    stop();error.clear();
    auto fail=[&](const std::string& value)->bool {
        error=value;backend_->error=value;backend_->event("error",value);return false;
    };
    if(!validate(config,error)) return fail(error);
    if((config.enableHttps||config.enableSocksTls)&&(!regularFile(config.tlsCertFile)||!regularFile(config.tlsKeyFile)))
        return fail(u8"Не найден TLS-сертификат или закрытый ключ. Перед запуском создайте либо выберите оба PEM-файла.");
    unsigned short metricsPort=0;
    if(!preflight(config,metricsPort,error)) return fail(error);
    std::string password;
    if(!randomPassword(password)) return fail(u8"Windows не смогла создать случайный пароль для локальных счётчиков.");
    auto monitor=std::make_shared<Monitor>();
    monitor->port=metricsPort;monitor->expected=serviceCount(config);monitor->snapshot.expectedServices=monitor->expected;
    monitor->authorization=L"Authorization: Basic "+utf16(base64("metrics:"+password))+L"\r\nConnection: close\r\n";
    std::string json=buildGostConfig(config,metricsPort,password);
    if(!password.empty())SecureZeroMemory(&password[0],password.size());
    const bool started=backend_->process.start(enginePath(),{L"-C",L"-"},json,error);
    if(!json.empty())SecureZeroMemory(&json[0],json.size());
    if(!started)return fail(error);
    try{backend_->worker=std::thread(monitorLoop,monitor);}
    catch(...){backend_->process.stop();return fail(u8"Не удалось запустить получение локальных счётчиков.");}
    backend_->monitor=monitor;backend_->expected=monitor->expected;
    backend_->started=GetTickCount64();backend_->ended=backend_->started;backend_->active=true;
    backend_->readyLogged=false;backend_->metricsWarning=false;backend_->error.clear();
    backend_->lastHandlerErrors=backend_->lastUpstreamErrors=backend_->lastFailedServices=0;
    backend_->event("info",u8"Ядро GOST запущено. Проверяем службы через защищённые локальные счётчики: "+std::to_string(backend_->expected)+".");
    return true;
}
void Server::stop() {
    if(!backend_)return;
    const bool wasActive=backend_->active;
    if(backend_->monitor)backend_->monitor->stop=true;
    backend_->process.stop();
    backend_->stopMonitor();
    if(wasActive){backend_->active=false;backend_->ended=GetTickCount64();backend_->event("info",u8"GOST остановлен. Его порты и активные сеансы закрыты.");}
}
bool Server::running() const{backend_->poll();return backend_->active;}
Stats Server::stats() const{backend_->poll();return backend_->snapshot();}
std::vector<Event> Server::events(std::uint64_t afterId) const {
    backend_->poll();std::vector<Event> result;
    for(const Event& event:backend_->log)if(event.id>afterId)result.push_back(event);
    return result;
}
std::string Server::lastError() const{backend_->poll();return backend_->error;}
}
