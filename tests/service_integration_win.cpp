// Windows-only SCM integration for an explicitly opted-in, disposable
// GitHub-hosted runner. It refuses pre-existing application installations.
// The firewall probe adds/removes only this fresh installation's own temporary
// rules, restricted to loopback clients. Existing policies, RDP, routing,
// trust-store and account settings are not changed.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlobj.h>
#include <aclapi.h>
#include <tlhelp32.h>
#include <gdiplus.h>
#include <netfw.h>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include "service_host.h"
#include "service_firewall.h"

namespace {
const wchar_t* ServiceName=L"ProxyServer21";
unsigned groups=0;
void require(bool ok,const std::string& reason){if(!ok)throw std::runtime_error(reason);}
void requireApi(bool ok,const char* prefix,const std::string& error){if(!ok)throw std::runtime_error(std::string(prefix)+error);}
void passed(const char* label){++groups;std::cout<<"PASS "<<groups<<": "<<label<<"\n"<<std::flush;}
std::wstring env(const wchar_t* name){wchar_t value[32768]={};DWORD n=GetEnvironmentVariableW(name,value,32768);return n&&n<32768?std::wstring(value,n):L"";}
std::wstring self(){wchar_t value[32768]={};DWORD n=GetModuleFileNameW(nullptr,value,32768);require(n&&n<32768,"GetModuleFileName failed");return std::wstring(value,n);}
std::wstring known(REFKNOWNFOLDERID id){PWSTR value=nullptr;HRESULT hr=SHGetKnownFolderPath(id,0,nullptr,&value);require(SUCCEEDED(hr)&&value,"Known folder lookup failed");std::wstring result(value);CoTaskMemFree(value);return result;}
bool exists(const std::wstring& path){return GetFileAttributesW(path.c_str())!=INVALID_FILE_ATTRIBUTES;}
bool samePath(const std::wstring& a,const std::wstring& b){return _wcsicmp(a.c_str(),b.c_str())==0;}
struct Handle {HANDLE value;explicit Handle(HANDLE h=nullptr):value(h){}~Handle(){if(value&&value!=INVALID_HANDLE_VALUE)CloseHandle(value);}Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;};
struct ScHandle {SC_HANDLE value;explicit ScHandle(SC_HANDLE h=nullptr):value(h){}~ScHandle(){if(value)CloseServiceHandle(value);}ScHandle(const ScHandle&)=delete;ScHandle& operator=(const ScHandle&)=delete;};
struct Socket {SOCKET value;explicit Socket(SOCKET s=INVALID_SOCKET):value(s){}~Socket(){if(value!=INVALID_SOCKET)closesocket(value);}Socket(const Socket&)=delete;Socket& operator=(const Socket&)=delete;};
template<class T> struct Com {T* value=nullptr;~Com(){if(value)value->Release();}Com(){}Com(const Com&)=delete;Com& operator=(const Com&)=delete;};
struct Bstr {BSTR value;explicit Bstr(const std::wstring& text):value(SysAllocStringLen(text.data(),static_cast<UINT>(text.size()))){require(value!=nullptr,"Firewall BSTR allocation failed");}~Bstr(){SysFreeString(value);}Bstr(const Bstr&)=delete;Bstr& operator=(const Bstr&)=delete;};

typedef HRESULT (STDMETHODCALLTYPE INetFwRule::*RuleTextGetter)(BSTR*);
std::wstring ruleText(INetFwRule* rule,RuleTextGetter getter){
    BSTR value=nullptr;HRESULT result=(rule->*getter)(&value);
    std::wstring text=SUCCEEDED(result)?std::wstring(value?value:L"",value?SysStringLen(value):0):L"!HRESULT:"+std::to_wstring(static_cast<unsigned long>(result));
    SysFreeString(value);return text;
}
std::vector<std::wstring> firewallSnapshot(INetFwPolicy2* policy,INetFwRules* rules,const std::wstring& ownPrefix){
    std::vector<std::wstring> snapshot;
    for(NET_FW_PROFILE_TYPE2 profile:{NET_FW_PROFILE2_DOMAIN,NET_FW_PROFILE2_PRIVATE,NET_FW_PROFILE2_PUBLIC}){
        VARIANT_BOOL enabled=VARIANT_FALSE;NET_FW_ACTION inbound=NET_FW_ACTION_BLOCK,outbound=NET_FW_ACTION_BLOCK;
        require(SUCCEEDED(policy->get_FirewallEnabled(profile,&enabled))&&SUCCEEDED(policy->get_DefaultInboundAction(profile,&inbound))&&SUCCEEDED(policy->get_DefaultOutboundAction(profile,&outbound)),"Cannot snapshot existing firewall profile policies");
        snapshot.push_back(L"PROFILE|"+std::to_wstring(profile)+L"|"+std::to_wstring(enabled)+L"|"+std::to_wstring(inbound)+L"|"+std::to_wstring(outbound));
    }
    Com<IUnknown> unknown;require(SUCCEEDED(rules->get__NewEnum(&unknown.value)),"Cannot enumerate existing firewall rules");
    Com<IEnumVARIANT> enumeration;require(SUCCEEDED(unknown.value->QueryInterface(IID_IEnumVARIANT,reinterpret_cast<void**>(&enumeration.value))),"Cannot query firewall enumerator");
    for(;;){
        VARIANT item;VariantInit(&item);ULONG count=0;HRESULT result=enumeration.value->Next(1,&item,&count);
        if(FAILED(result)){VariantClear(&item);throw std::runtime_error("Firewall enumeration failed");}
        if(result==S_FALSE||!count){VariantClear(&item);break;}
        Com<INetFwRule> rule;IUnknown* object=item.vt==VT_DISPATCH?item.pdispVal:item.vt==VT_UNKNOWN?item.punkVal:nullptr;
        HRESULT queried=object?object->QueryInterface(__uuidof(INetFwRule),reinterpret_cast<void**>(&rule.value)):E_NOINTERFACE;VariantClear(&item);
        require(SUCCEEDED(queried)&&rule.value,"Unexpected firewall rule enumeration object");
        const std::wstring name=ruleText(rule.value,&INetFwRule::get_Name);
        if(name.compare(0,ownPrefix.size(),ownPrefix)==0)continue;
        std::wstring row=L"RULE|"+name;
        const RuleTextGetter getters[]={&INetFwRule::get_Grouping,&INetFwRule::get_Description,&INetFwRule::get_ApplicationName,&INetFwRule::get_ServiceName,&INetFwRule::get_LocalPorts,&INetFwRule::get_RemotePorts,&INetFwRule::get_LocalAddresses,&INetFwRule::get_RemoteAddresses,&INetFwRule::get_InterfaceTypes};
        for(auto getter:getters){std::wstring value=ruleText(rule.value,getter);row+=L"|"+std::to_wstring(value.size())+L":"+value;}
        long protocol=0,profiles=0;VARIANT_BOOL enabled=0,edge=0;NET_FW_RULE_DIRECTION direction=NET_FW_RULE_DIR_IN;NET_FW_ACTION action=NET_FW_ACTION_BLOCK;
        require(SUCCEEDED(rule.value->get_Protocol(&protocol))&&SUCCEEDED(rule.value->get_Profiles(&profiles))&&SUCCEEDED(rule.value->get_Enabled(&enabled))&&SUCCEEDED(rule.value->get_EdgeTraversal(&edge))&&SUCCEEDED(rule.value->get_Direction(&direction))&&SUCCEEDED(rule.value->get_Action(&action)),"Cannot snapshot existing firewall rule state");
        row+=L"|"+std::to_wstring(protocol)+L"|"+std::to_wstring(profiles)+L"|"+std::to_wstring(enabled)+L"|"+std::to_wstring(edge)+L"|"+std::to_wstring(direction)+L"|"+std::to_wstring(action);snapshot.push_back(row);
    }
    std::sort(snapshot.begin(),snapshot.end());return snapshot;
}
std::vector<std::wstring> verifyFirewallPlan(INetFwRules* rules,const proxy::Config& proxy,const mtproto::Config& mt,const std::wstring& directory){
    std::vector<service_firewall::Rule> plan;std::string error;requireApi(service_firewall::makePlan(proxy,mt,directory,false,plan,error),"Cannot generate test firewall plan: ",error);
    require(plan.size()==2,"Firewall probe must have only GOST TCP and UDP rules");std::vector<std::wstring> names;
    for(const auto& expected:plan){
        Bstr name(expected.name);Com<INetFwRule> actual;require(SUCCEEDED(rules->Item(name.value,&actual.value))&&actual.value,"Expected owned firewall rule is absent");
        require(ruleText(actual.value,&INetFwRule::get_Grouping)==service_firewall::groupName()&&ruleText(actual.value,&INetFwRule::get_Description)==service_firewall::description(),"Firewall ownership marker mismatch");
        require(samePath(ruleText(actual.value,&INetFwRule::get_ApplicationName),expected.application),"Firewall program scope mismatch");
        require(ruleText(actual.value,&INetFwRule::get_LocalPorts)==expected.localPorts,"Firewall local port normalization mismatch");
        require(ruleText(actual.value,&INetFwRule::get_LocalAddresses)==expected.localAddresses,"Firewall local address normalization mismatch");
        const std::wstring remote=ruleText(actual.value,&INetFwRule::get_RemoteAddresses);
        std::cout<<"FIREWALL_REMOTE_SCOPE: "<<std::string(remote.begin(),remote.end())<<"\n";
        require(remote==L"127.0.0.1"||remote==L"127.0.0.1/32"||remote==L"127.0.0.1/255.255.255.255","Firewall client restriction is not one exact loopback host: "+std::string(remote.begin(),remote.end()));
        long protocol=0,profiles=0;VARIANT_BOOL enabled=0,edge=0;NET_FW_RULE_DIRECTION direction=NET_FW_RULE_DIR_OUT;NET_FW_ACTION action=NET_FW_ACTION_BLOCK;
        require(SUCCEEDED(actual.value->get_Protocol(&protocol))&&protocol==expected.protocol&&SUCCEEDED(actual.value->get_Profiles(&profiles))&&profiles==NET_FW_PROFILE2_ALL&&SUCCEEDED(actual.value->get_Enabled(&enabled))&&enabled==VARIANT_TRUE&&SUCCEEDED(actual.value->get_EdgeTraversal(&edge))&&edge==VARIANT_FALSE&&SUCCEEDED(actual.value->get_Direction(&direction))&&direction==NET_FW_RULE_DIR_IN&&SUCCEEDED(actual.value->get_Action(&action))&&action==NET_FW_ACTION_ALLOW,"Firewall rule flags mismatch");
        names.push_back(expected.name);
    }
    return names;
}
void firewallRoundTrip(const service_host::Profile& profile,const std::wstring& directory,unsigned short changedPort){
    HRESULT initialized=CoInitializeEx(nullptr,COINIT_MULTITHREADED);require(SUCCEEDED(initialized)||initialized==RPC_E_CHANGED_MODE,"Firewall COM apartment initialization failed");
    struct Uninitialize{bool active;~Uninitialize(){if(active)CoUninitialize();}} uninitialize={SUCCEEDED(initialized)};
    Com<INetFwPolicy2> policy;require(SUCCEEDED(CoCreateInstance(__uuidof(NetFwPolicy2),nullptr,CLSCTX_INPROC_SERVER,__uuidof(INetFwPolicy2),reinterpret_cast<void**>(&policy.value))),"Cannot create firewall policy COM object");
    Com<INetFwRules> rules;require(SUCCEEDED(policy.value->get_Rules(&rules.value)),"Cannot open firewall rule collection");
    const std::wstring prefix=service_firewall::installationPrefix(directory);const auto before=firewallSnapshot(policy.value,rules.value,prefix);
    proxy::Config probe=profile.proxy;probe.bindAddress="0.0.0.0";probe.allowIp="127.0.0.1";probe.enableSocksUdp=true;probe.udpPortMin=20000;probe.udpPortMax=20001;
    std::string error;bool attempted=false;std::vector<std::wstring> names;
    try{
        attempted=true;requireApi(service_firewall::apply(probe,profile.mt,directory,false,error),"First scoped firewall apply failed: ",error);names=verifyFirewallPlan(rules.value,probe,profile.mt,directory);
        require(firewallSnapshot(policy.value,rules.value,prefix)==before,"First apply changed an unrelated rule or firewall profile policy");
        requireApi(service_firewall::apply(probe,profile.mt,directory,false,error),"Identical firewall reapply failed: ",error);verifyFirewallPlan(rules.value,probe,profile.mt,directory);
        require(firewallSnapshot(policy.value,rules.value,prefix)==before,"Idempotent apply changed an unrelated rule or firewall profile policy");
        probe.httpPort=changedPort;requireApi(service_firewall::apply(probe,profile.mt,directory,false,error),"Changed firewall plan failed: ",error);const auto changed=verifyFirewallPlan(rules.value,probe,profile.mt,directory);
        for(const auto& old:names)if(std::find(changed.begin(),changed.end(),old)==changed.end()){Bstr key(old);Com<INetFwRule> rule;require(FAILED(rules.value->Item(key.value,&rule.value)),"Superseded owned firewall rule remains");}
        names.insert(names.end(),changed.begin(),changed.end());
        require(firewallSnapshot(policy.value,rules.value,prefix)==before,"Plan update changed an unrelated rule or firewall profile policy");
        requireApi(service_firewall::remove(directory,error),"Owned firewall cleanup failed: ",error);
        for(const auto& old:names){Bstr key(old);Com<INetFwRule> rule;require(FAILED(rules.value->Item(key.value,&rule.value)),"Owned firewall rule remains after cleanup");}
        require(firewallSnapshot(policy.value,rules.value,prefix)==before,"Firewall cleanup changed existing profile policy or unrelated/RDP rules");attempted=false;
    }catch(...){if(attempted){std::string cleanup;if(!service_firewall::remove(directory,cleanup))std::cerr<<"Test-owned firewall cleanup failed: "<<cleanup<<"\n";}throw;}
}

template<class F> void eventually(F check,DWORD milliseconds,const char* message){
    const ULONGLONG deadline=GetTickCount64()+milliseconds;
    do{if(check())return;Sleep(100);}while(GetTickCount64()<deadline);
    throw std::runtime_error(message);
}
void requireCI(){
    require(env(L"GITHUB_ACTIONS")==L"true"&&env(L"RUNNER_ENVIRONMENT")==L"github-hosted"&&env(L"ENABLE_PROXY_SERVICE_TESTS")==L"1",
            "Refusing SCM tests: requires an explicitly opted-in disposable GitHub-hosted runner");
    require(service_host::isElevated(),"SCM tests require the runner's administrator token");
}
DWORD servicePid(){
    ScHandle manager(OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT));if(!manager.value)return 0;
    ScHandle service(OpenServiceW(manager.value,ServiceName,SERVICE_QUERY_STATUS));if(!service.value)return 0;
    SERVICE_STATUS_PROCESS status={};DWORD bytes=0;
    if(!QueryServiceStatusEx(service.value,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&status),sizeof(status),&bytes))return 0;
    return status.dwProcessId;
}
std::vector<DWORD> ownedEnginePids(const std::wstring& executable,DWORD parent){
    std::vector<DWORD> ids;Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));
    require(snapshot.value!=INVALID_HANDLE_VALUE,"Process snapshot failed");
    PROCESSENTRY32W entry={};entry.dwSize=sizeof(entry);
    if(Process32FirstW(snapshot.value,&entry))do{
        if(entry.th32ParentProcessID!=parent)continue;
        Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,entry.th32ProcessID));if(!process.value)continue;
        wchar_t path[32768]={};DWORD size=32768;
        if(QueryFullProcessImageNameW(process.value,0,path,&size)&&samePath(std::wstring(path,size),executable))ids.push_back(entry.th32ProcessID);
    }while(Process32NextW(snapshot.value,&entry));
    return ids;
}
void crashOwnedEngine(DWORD pid,const std::wstring& executable,DWORD expectedParent){
    const auto ids=ownedEnginePids(executable,expectedParent);
    require(std::find(ids.begin(),ids.end(),pid)!=ids.end(),"Crash probe PID is not a child of this test service");
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_TERMINATE|SYNCHRONIZE,FALSE,pid));
    require(process.value!=nullptr,"Cannot open this test service's GOST child for the crash probe");
    wchar_t path[32768]={};DWORD size=32768;
    require(QueryFullProcessImageNameW(process.value,0,path,&size)&&samePath(std::wstring(path,size),executable),"Crash probe executable changed");
    require(TerminateProcess(process.value,23)!=FALSE,"Owned engine crash probe failed");
    require(WaitForSingleObject(process.value,10000)==WAIT_OBJECT_0,"Owned engine did not exit after crash probe");
}
void sendAll(SOCKET s,const std::string& data){std::size_t offset=0;while(offset<data.size()){int n=send(s,data.data()+offset,static_cast<int>((std::min)(data.size()-offset,static_cast<std::size_t>(32768))),0);require(n>0,"Socket send failed");offset+=static_cast<std::size_t>(n);}}
std::string receive(SOCKET s,std::size_t size){std::string out(size,'\0');std::size_t offset=0;while(offset<size){int n=recv(s,&out[offset],static_cast<int>(size-offset),0);require(n>0,"Socket receive failed");offset+=static_cast<std::size_t>(n);}return out;}
SOCKET connectLocal(unsigned short port){
    SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(s==INVALID_SOCKET)return s;
    DWORD timeout=4000;setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout));setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout));
    sockaddr_in address={};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons(port);
    if(connect(s,reinterpret_cast<sockaddr*>(&address),sizeof(address))==SOCKET_ERROR){closesocket(s);return INVALID_SOCKET;}return s;
}
bool portOpen(unsigned short port){Socket s(connectLocal(port));return s.value!=INVALID_SOCKET;}
class Fixture {
    SOCKET listener_=INVALID_SOCKET;std::thread worker_;std::atomic<bool> stop_{false};bool http_;
    void run(){
        while(!stop_.load()){
            Socket client(accept(listener_,nullptr,nullptr));if(client.value==INVALID_SOCKET)break;
            DWORD timeout=4000;setsockopt(client.value,SOL_SOCKET,SO_RCVTIMEO,reinterpret_cast<const char*>(&timeout),sizeof(timeout));
            try{
                if(http_){
                    std::string request;char buffer[1024];
                    while(request.find("\r\n\r\n")==std::string::npos&&request.size()<16384){int n=recv(client.value,buffer,sizeof(buffer),0);if(n<=0)break;request.append(buffer,static_cast<std::size_t>(n));}
                    const std::string body="WINDOWS_SERVICE_HTTP_OK";
                    sendAll(client.value,"HTTP/1.1 200 OK\r\nContent-Length: "+std::to_string(body.size())+"\r\nConnection: close\r\n\r\n"+body);
                }else{
                    char buffer[16384];for(;;){int n=recv(client.value,buffer,sizeof(buffer),0);if(n<=0)break;sendAll(client.value,std::string(buffer,static_cast<std::size_t>(n)));}
                }
            }catch(...){/* Fixture client shutdown is expected in negative tests. */}
        }
    }
public:
    unsigned short port=0;
    explicit Fixture(bool http):http_(http){
        listener_=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);require(listener_!=INVALID_SOCKET,"Fixture socket failed");
        BOOL exclusive=TRUE;setsockopt(listener_,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof(exclusive));
        sockaddr_in address={};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        require(bind(listener_,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"Fixture bind failed");int size=sizeof(address);
        require(getsockname(listener_,reinterpret_cast<sockaddr*>(&address),&size)==0&&listen(listener_,8)==0,"Fixture listen failed");port=ntohs(address.sin_port);
        worker_=std::thread(&Fixture::run,this);
    }
    ~Fixture(){stop_.store(true);shutdown(listener_,SD_BOTH);closesocket(listener_);if(worker_.joinable())worker_.join();}
};
std::vector<unsigned short> freePorts(){
    std::vector<unsigned short> ports;std::vector<SOCKET> sockets;
    for(unsigned i=0;i<3;++i){SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);require(s!=INVALID_SOCKET,"Port reservation socket failed");sockets.push_back(s);sockaddr_in a={};a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);require(bind(s,reinterpret_cast<sockaddr*>(&a),sizeof(a))==0,"Port reservation failed");int size=sizeof(a);require(getsockname(s,reinterpret_cast<sockaddr*>(&a),&size)==0,"Port reservation name failed");ports.push_back(ntohs(a.sin_port));}
    for(SOCKET s:sockets)closesocket(s);
    return ports;
}
std::string basic(const std::string& value){const char* table="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";std::string out;unsigned accumulator=0,bits=0;for(unsigned char c:value){accumulator=(accumulator<<8)|c;bits+=8;while(bits>=6){bits-=6;out+=table[(accumulator>>bits)&63];}}if(bits)out+=table[(accumulator<<(6-bits))&63];while(out.size()%4)out+='=';return out;}
void socksRoundTrip(const proxy::Config& p,unsigned short target){
    Socket client(connectLocal(p.socksPort));require(client.value!=INVALID_SOCKET,"SOCKS listener unavailable");
    sendAll(client.value,std::string("\x05\x01\x02",3));require(receive(client.value,2)==std::string("\x05\x02",2),"SOCKS did not select password authentication");
    std::string auth(1,'\x01');auth+=static_cast<char>(p.user.size());auth+=p.user;auth+=static_cast<char>(p.password.size());auth+=p.password;
    sendAll(client.value,auth);require(receive(client.value,2)==std::string("\x01\x00",2),"SOCKS password rejected");
    std::string request("\x05\x01\x00\x01\x7f\x00\x00\x01",8);request+=static_cast<char>(target>>8);request+=static_cast<char>(target&255);sendAll(client.value,request);
    std::string reply=receive(client.value,4);require(reply[0]=='\x05'&&reply[1]=='\0',"SOCKS CONNECT rejected");
    if(reply[3]=='\x01')receive(client.value,6);else if(reply[3]=='\x04')receive(client.value,18);else if(reply[3]=='\x03'){unsigned size=static_cast<unsigned char>(receive(client.value,1)[0]);receive(client.value,size+2);}else throw std::runtime_error("Invalid SOCKS address type");
    std::string payload(65536,'\0');for(std::size_t i=0;i<payload.size();++i)payload[i]=static_cast<char>((i*37)&255);
    sendAll(client.value,payload);require(receive(client.value,payload.size())==payload,"SOCKS binary echo mismatch");
}
void noAnonymousSocks(const proxy::Config& p){Socket client(connectLocal(p.socksPort));require(client.value!=INVALID_SOCKET,"SOCKS auth-negative listener unavailable");sendAll(client.value,std::string("\x05\x01\x00",3));require(receive(client.value,2)==std::string("\x05\xff",2),"SOCKS allowed anonymous authentication");}
void httpRoundTrip(const proxy::Config& p,unsigned short target,bool authenticated){
    Socket client(connectLocal(p.httpPort));require(client.value!=INVALID_SOCKET,"HTTP listener unavailable");
    std::string request="GET http://127.0.0.1:"+std::to_string(target)+"/echo HTTP/1.1\r\nHost: 127.0.0.1:"+std::to_string(target)+"\r\nConnection: close\r\n";
    if(authenticated)request+="Proxy-Authorization: Basic "+basic(p.user+":"+p.password)+"\r\n";
    request+="\r\n";sendAll(client.value,request);
    std::string response;char buffer[4096];for(;;){int n=recv(client.value,buffer,sizeof(buffer),0);if(n<=0)break;response.append(buffer,static_cast<std::size_t>(n));require(response.size()<65536,"Oversized HTTP fixture response");}
    require(response.find(authenticated?" 200 ":" 407 ")!=std::string::npos,"Unexpected HTTP authentication status");
    if(authenticated)require(response.find("WINDOWS_SERVICE_HTTP_OK")!=std::string::npos,"HTTP response body missing");
}
std::string readFile(const std::wstring& path){Handle f(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr));require(f.value!=INVALID_HANDLE_VALUE,"Cannot read test-owned profile");DWORD size=GetFileSize(f.value,nullptr);require(size>0&&size<1024*1024,"Unexpected protected profile size");std::string data(size,'\0');DWORD read=0;require(ReadFile(f.value,&data[0],size,&read,nullptr)&&read==size,"Protected profile read failed");return data;}
void protectedAcl(const std::wstring& path){
    PACL dacl=nullptr;PSECURITY_DESCRIPTOR sd=nullptr;DWORD code=GetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()),SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,nullptr,nullptr,&dacl,nullptr,&sd);
    require(code==ERROR_SUCCESS&&sd&&dacl,"Protected path has no readable DACL");
    SECURITY_DESCRIPTOR_CONTROL control=0;DWORD revision=0;bool good=GetSecurityDescriptorControl(sd,&control,&revision)!=FALSE&&(control&SE_DACL_PROTECTED)!=0;
    for(DWORD i=0;i<dacl->AceCount&&good;++i){void* ace=nullptr;if(!GetAce(dacl,i,&ace)){good=false;break;}ACE_HEADER* header=static_cast<ACE_HEADER*>(ace);if(header->AceType==ACCESS_ALLOWED_ACE_TYPE){auto* allowed=static_cast<ACCESS_ALLOWED_ACE*>(ace);PSID sid=&allowed->SidStart;if(IsWellKnownSid(sid,WinWorldSid)||IsWellKnownSid(sid,WinBuiltinUsersSid)||IsWellKnownSid(sid,WinAuthenticatedUserSid))good=false;}}
    LocalFree(sd);require(good,"Test service directory ACL is not protected from unprivileged broad groups");
}
std::string productBytes(const std::wstring& path){
    Handle file(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    require(file.value!=INVALID_HANDLE_VALUE,"Cannot read product executable for the service gate");
    BY_HANDLE_FILE_INFORMATION information={};LARGE_INTEGER size={};
    require(GetFileInformationByHandle(file.value,&information)&&!(information.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))&&GetFileSizeEx(file.value,&size)&&size.QuadPart>0&&size.QuadPart<=64*1024*1024,"Product executable is not a bounded normal file");
    std::string bytes(static_cast<std::size_t>(size.QuadPart),'\0');DWORD count=0;
    require(ReadFile(file.value,&bytes[0],static_cast<DWORD>(bytes.size()),&count,nullptr)&&count==bytes.size(),"Cannot read complete product executable");return bytes;
}
void installRealProduct(const std::wstring& directory,const std::wstring& root){
    const std::wstring prefix=root+L"\\host-";
    require(directory.size()==prefix.size()+32&&samePath(directory.substr(0,prefix.size()),prefix)&&directory.find_first_not_of(L"0123456789abcdef",prefix.size())==std::wstring::npos,"Refusing product copy outside this test's fresh protected host directory");
    const std::wstring source=env(L"PROXY_GUI_EXE"),destination=directory+L"\\ProxyServer.exe";
    require(!source.empty()&&!samePath(source,destination),"Actual production EXE path is absent or equals the installed destination");
    ScHandle manager(OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT));require(manager.value!=nullptr,"Cannot query SCM before product copy");
    ScHandle service(OpenServiceW(manager.value,ServiceName,SERVICE_QUERY_STATUS));require(service.value!=nullptr,"Fresh test service disappeared before product copy");
    SERVICE_STATUS_PROCESS status={};DWORD count=0;
    require(QueryServiceStatusEx(service.value,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&status),sizeof(status),&count)&&status.dwCurrentState==SERVICE_STOPPED&&status.dwProcessId==0,"Refusing product copy while the fresh test service is not stopped");
    const std::string bytes=productBytes(source);protectedAcl(destination);
    {
        // Keep the protected destination file and its security descriptor. CopyFile
        // can copy the source ACL on Windows, so replace bytes through this handle.
        Handle file(CreateFileW(destination.c_str(),GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        require(file.value!=INVALID_HANDLE_VALUE,"Cannot open the fresh protected service executable");BY_HANDLE_FILE_INFORMATION information={};
        require(GetFileInformationByHandle(file.value,&information)&&information.nNumberOfLinks==1&&!(information.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)),"Fresh service executable is linked or is not a normal file");
        count=0;require(WriteFile(file.value,bytes.data(),static_cast<DWORD>(bytes.size()),&count,nullptr)&&count==bytes.size()&&SetEndOfFile(file.value)&&FlushFileBuffers(file.value),"Cannot replace the fresh service executable with the actual product");
    }
    protectedAcl(destination);require(productBytes(destination)==bytes,"Installed product EXE differs from the MSVC build byte for byte");
}
struct FindWindowContext{DWORD process;HWND result;};
BOOL CALLBACK findWindow(HWND window,LPARAM parameter){auto* c=reinterpret_cast<FindWindowContext*>(parameter);DWORD pid=0;GetWindowThreadProcessId(window,&pid);if(pid==c->process&&GetWindow(window,GW_OWNER)==nullptr&&IsWindowVisible(window)){c->result=window;return FALSE;}return TRUE;}
bool captureOwnWindow(HWND window,DWORD expectedProcess){
    SetProcessDPIAware();
    const std::wstring destination=env(L"PROXY_UI_SCREENSHOT"),expectedImage=env(L"PROXY_GUI_EXE");
    if(destination.empty()||expectedImage.empty()||!IsWindow(window))return false;
    DWORD pid=0;GetWindowThreadProcessId(window,&pid);if(pid!=expectedProcess)return false;
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid));if(!process.value)return false;
    wchar_t image[32768]={};DWORD length=32768;
    if(!QueryFullProcessImageNameW(process.value,0,image,&length)||!samePath(std::wstring(image,length),expectedImage))return false;
    RECT rectangle={};if(!GetWindowRect(window,&rectangle))return false;
    int width=rectangle.right-rectangle.left,height=rectangle.bottom-rectangle.top;
    if(width<1||height<1||width>5000||height>5000)return false;
    ULONG_PTR token=0;Gdiplus::GdiplusStartupInput input;
    if(Gdiplus::GdiplusStartup(&token,&input,nullptr)!=Gdiplus::Ok)return false;
    bool saved=false;HDC source=GetDC(window),memory=source?CreateCompatibleDC(source):nullptr;
    HBITMAP bitmap=memory?CreateCompatibleBitmap(source,width,height):nullptr;
    if(bitmap){
        HGDIOBJ previous=SelectObject(memory,bitmap);
        if(PrintWindow(window,memory,2)){
            UINT count=0,size=0;
            if(Gdiplus::GetImageEncodersSize(&count,&size)==Gdiplus::Ok&&size){
                std::vector<unsigned char> storage(size);auto* encoders=reinterpret_cast<Gdiplus::ImageCodecInfo*>(storage.data());
                if(Gdiplus::GetImageEncoders(count,size,encoders)==Gdiplus::Ok){
                    for(UINT index=0;index<count;++index)if(wcscmp(encoders[index].MimeType,L"image/png")==0){
                        Gdiplus::Bitmap capture(bitmap,nullptr);saved=capture.Save(destination.c_str(),&encoders[index].Clsid,nullptr)==Gdiplus::Ok;break;
                    }
                }
            }
        }
        SelectObject(memory,previous);DeleteObject(bitmap);
    }
    if(memory)DeleteDC(memory);
    if(source)ReleaseDC(window,source);
    Gdiplus::GdiplusShutdown(token);return saved;
}
void optionalScreenshot(HWND window,DWORD guiProcess){
    if(env(L"PROXY_UI_SCREENSHOT").empty())return;
    DWORD_PTR ignored=0;
    if(!SendMessageTimeoutW(window,WM_COMMAND,MAKEWPARAM(105,BN_CLICKED),0,SMTO_ABORTIFHUNG,2000,&ignored)){std::cout<<"SCREENSHOT_WARNING: GUI navigation timed out\n";return;}
    Sleep(500);const std::wstring executable=self();
    std::wstring command=L"\""+executable+L"\" --capture-window "+std::to_wstring(reinterpret_cast<std::uintptr_t>(window))+L" "+std::to_wstring(guiProcess);
    std::vector<wchar_t> writable(command.begin(),command.end());writable.push_back(0);STARTUPINFOW startup={};startup.cb=sizeof(startup);PROCESS_INFORMATION information={};
    if(!CreateProcessW(executable.c_str(),writable.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&information)){std::cout<<"SCREENSHOT_WARNING: capture helper unavailable\n";return;}
    Handle process(information.hProcess),thread(information.hThread);DWORD code=1;
    if(WaitForSingleObject(process.value,10000)!=WAIT_OBJECT_0){TerminateProcess(process.value,43);WaitForSingleObject(process.value,2000);}
    else GetExitCodeProcess(process.value,&code);
    std::cout<<(code==0?"SCREENSHOT_SAVED: windows-service-ui.png\n":"SCREENSHOT_WARNING: optional own-window capture unavailable\n");
}
void closeRealGui(){
    const std::wstring executable=env(L"PROXY_GUI_EXE");require(!executable.empty()&&exists(executable),"Real GUI executable not provided for lifecycle check");
    const std::wstring directory=executable.substr(0,executable.find_last_of(L"\\/"));const std::wstring ini=directory+L"\\proxy.ini";
    require(!exists(ini),"Refusing to overwrite an existing GUI INI in the build output");
    const wchar_t preference[]=L"\xFEFF[proxy]\r\nversion=2\r\nclose_to_tray=0\r\n";
    {Handle file(CreateFileW(ini.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));require(file.value!=INVALID_HANDLE_VALUE,"Cannot create isolated GUI preference fixture");DWORD count=0;require(WriteFile(file.value,preference,static_cast<DWORD>(sizeof(preference)-sizeof(wchar_t)),&count,nullptr)!=FALSE,"GUI fixture write failed");}
    std::wstring command=L"\""+executable+L"\"";std::vector<wchar_t> writable(command.begin(),command.end());writable.push_back(0);STARTUPINFOW startup={};startup.cb=sizeof(startup);PROCESS_INFORMATION process={};
    bool started=CreateProcessW(executable.c_str(),writable.data(),nullptr,nullptr,FALSE,0,nullptr,directory.c_str(),&startup,&process)!=FALSE;
    if(!started){DeleteFileW(ini.c_str());throw std::runtime_error("Could not start real Windows GUI");}
    Handle child(process.hProcess),thread(process.hThread);FindWindowContext context={process.dwProcessId,nullptr};
    try{
        eventually([&]{EnumWindows(findWindow,reinterpret_cast<LPARAM>(&context));return context.result!=nullptr;},15000,"GUI main window did not appear");
        // Discovery must finish before close; no fields are edited by this probe.
        Sleep(3000);optionalScreenshot(context.result,process.dwProcessId);
        require(PostMessageW(context.result,WM_CLOSE,0,0)!=FALSE,"Cannot request GUI close");
        require(WaitForSingleObject(child.value,15000)==WAIT_OBJECT_0,"GUI did not exit after an ordinary WM_CLOSE");
        DWORD exit=1;require(GetExitCodeProcess(child.value,&exit)&&exit==0,"GUI exited with an error");
    }catch(...){TerminateProcess(child.value,42);WaitForSingleObject(child.value,5000);DeleteFileW(ini.c_str());throw;}
    require(DeleteFileW(ini.c_str())!=FALSE,"Cannot remove own GUI preference fixture");
}
}

int wmain(int argc,wchar_t** argv){
    int serviceExit=0;if(argc==2&&service_host::dispatchIfService(argv[1],serviceExit))return serviceExit;
    bool installedByThisTest=false;std::wstring installedDirectory;
    try{
        requireCI();
        if(argc==4&&wcscmp(argv[1],L"--capture-window")==0){
            wchar_t* end=nullptr;unsigned long long raw=_wcstoui64(argv[2],&end,10);if(!end||*end)return 2;
            unsigned long pid=wcstoul(argv[3],&end,10);if(!end||*end||!pid)return 2;
            return captureOwnWindow(reinterpret_cast<HWND>(static_cast<std::uintptr_t>(raw)),static_cast<DWORD>(pid))?0:2;
        }
        const std::wstring dataRoot=known(FOLDERID_ProgramData)+L"\\ProxyServer21";
        const std::wstring installRoot=known(FOLDERID_ProgramFilesX64)+L"\\ProxyServer21";
        require(!exists(dataRoot)&&!exists(installRoot),"Refusing to touch pre-existing ProxyServer21 data/program directories");
        ScHandle manager(OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT));require(manager.value!=nullptr,"Cannot query SCM");
        ScHandle previous(OpenServiceW(manager.value,ServiceName,SERVICE_QUERY_STATUS));require(!previous.value&&GetLastError()==ERROR_SERVICE_DOES_NOT_EXIST,"Refusing to touch an existing service or unknown SCM state");
        WSADATA winsock={};require(WSAStartup(MAKEWORD(2,2),&winsock)==0,"WinSock initialization failed");
        Fixture echo(false),http(true);const auto ports=freePorts();
        service_host::Profile profile;profile.manageFirewall=false;profile.proxyAutoStart=false;profile.mtAutoStart=false;
        profile.proxy.bindAddress="127.0.0.1";profile.proxy.user="CI[user];#21";profile.proxy.password="CI-only_Initial-Password_21";
        profile.proxy.socksPort=ports[0];profile.proxy.httpPort=ports[1];profile.proxy.enableSocksUdp=false;
        profile.proxy.upstreamUser="ci-inactive-upstream";profile.proxy.upstreamPassword="CI-only_Upstream-Password_21";
        profile.mt.bindAddress="127.0.0.1";profile.mt.listenPort=ports[2];profile.tlsDomain="www.microsoft.com";
        std::string error;requireApi(service_host::install(profile,error),"Install failed: ",error);installedByThisTest=true;
        service_host::State state;requireApi(service_host::getState(state,error),"Installed state failed: ",error);installedDirectory=state.installDir;
        require(state.installed&&state.scmState==SERVICE_STOPPED,"Install did not leave a stopped SCM service");
        require(!installedDirectory.empty()&&exists(installedDirectory+L"\\ProxyServer.exe"),"Protected service binary absent");
        protectedAcl(dataRoot);protectedAcl(installRoot);protectedAcl(installedDirectory);
        require(readFile(dataRoot+L"\\profile.dpapi").find(profile.proxy.password)==std::string::npos,"Protected profile contains plaintext password");
        installRealProduct(installedDirectory,installRoot);
        passed("protected install, actual production EXE service host, stopped SCM state, DPAPI storage and ACLs");
        firewallRoundTrip(profile,installedDirectory,ports[2]);
        passed("real firewall COM apply, identical reapply, update and owned cleanup preserve all existing profiles/rules");
        requireApi(service_host::startService(error),"SCM start failed: ",error);
        eventually([&]{return service_host::getState(state,error)&&state.reachable;},30000,"Service IPC did not become reachable");
        require(!state.proxyRunning&&!state.mtRunning,"Disabled boot options unexpectedly started an engine");
        const std::wstring gost=installedDirectory+L"\\components\\gost.exe";
        require(ownedEnginePids(gost,servicePid()).empty(),"GOST exists despite disabled boot option");
        service_host::Profile loaded;requireApi(service_host::loadProfile(loaded,error),"Profile load failed: ",error);
        require(loaded.proxy.user==profile.proxy.user&&loaded.proxy.password==profile.proxy.password&&loaded.proxy.upstreamPassword==profile.proxy.upstreamPassword&&!loaded.manageFirewall,"Initial protected profile roundtrip failed");
        passed("SCM startup with both engines disabled and exact secret roundtrip");
        mtproto::Config telegram=profile.mt;require(mtproto::generateSecret(profile.tlsDomain,telegram.secret,error),"MT secret generation failed");telegram.publicHost="203.0.113.7";
        requireApi(service_host::saveTelegram(telegram,false,profile.tlsDomain,error),"MT-only save failed: ",error);
        require(service_host::loadProfile(loaded,error)&&loaded.mt.secret==telegram.secret&&loaded.proxy.password==profile.proxy.password&&loaded.proxy.upstreamPassword==profile.proxy.upstreamPassword,"MT save changed proxy settings");
        profile.proxy.password="CI-only_Changed-Password_21";profile.proxy.maxConnections=41;profile.proxy.connectTimeoutSeconds=7;profile.proxy.idleTimeoutSeconds=90;
        requireApi(service_host::saveProxy(profile.proxy,false,error),"Proxy-only save failed: ",error);
        require(service_host::loadProfile(loaded,error)&&loaded.proxy.password==profile.proxy.password&&loaded.proxy.maxConnections==41&&loaded.mt.secret==telegram.secret&&loaded.tlsDomain==profile.tlsDomain,"Proxy save changed MT settings");
        passed("independent proxy/MT saves preserve the other page and credentials");
        requireApi(service_host::command(service_host::Command::StartProxy,error),"Proxy start command failed: ",error);
        eventually([&]{return service_host::getState(state,error)&&state.reachable&&state.proxyRunning&&portOpen(profile.proxy.socksPort)&&portOpen(profile.proxy.httpPort);},30000,"GOST proxy listeners did not become ready");
        noAnonymousSocks(profile.proxy);socksRoundTrip(profile.proxy,echo.port);httpRoundTrip(profile.proxy,http.port,false);httpRoundTrip(profile.proxy,http.port,true);
        passed("real GOST SOCKS5/HTTP authentication and loopback payload transfer on Windows");
        const DWORD beforeGui=servicePid();closeRealGui();require(beforeGui&&servicePid()==beforeGui,"GUI close changed the service process");socksRoundTrip(profile.proxy,echo.port);
        passed("real GUI opens and exits while the Windows service and proxy remain alive");
        const DWORD parent=servicePid();auto pids=ownedEnginePids(gost,parent);require(pids.size()==1,"Expected exactly one service-owned GOST process");const DWORD first=pids[0];
        const auto beforeRestarts=state.proxyRestarts;crashOwnedEngine(first,gost,parent);
        eventually([&]{if(!service_host::getState(state,error)||!state.proxyRunning||state.proxyRestarts<=beforeRestarts)return false;auto current=ownedEnginePids(gost,parent);return current.size()==1&&current[0]!=first&&portOpen(profile.proxy.socksPort);},45000,"Owned GOST crash was not recovered through the watchdog");
        socksRoundTrip(profile.proxy,echo.port);passed("owned GOST crash triggers bounded service recovery");
        pids=ownedEnginePids(gost,parent);require(pids.size()==1,"Recovered GOST process missing");crashOwnedEngine(pids[0],gost,parent);
        requireApi(service_host::command(service_host::Command::StopProxy,error),"Stop during recovery failed: ",error);
        eventually([&]{return ownedEnginePids(gost,parent).empty()&&!portOpen(profile.proxy.socksPort)&&!portOpen(profile.proxy.httpPort);},20000,"Stopped proxy still owns listeners or child process");
        Sleep(7000);require(ownedEnginePids(gost,parent).empty()&&!portOpen(profile.proxy.socksPort),"A pending watchdog retry restarted a deliberately stopped proxy");
        passed("explicit stop cancels pending recovery and releases processes/ports");
        requireApi(service_host::saveProxy(profile.proxy,true,error),"Persist boot option failed: ",error);
        requireApi(service_host::stopService(error),"SCM stop failed: ",error);
        eventually([&]{return !portOpen(profile.proxy.socksPort)&&!portOpen(profile.proxy.httpPort);},15000,"SCM stop left proxy ports open");
        requireApi(service_host::startService(error),"SCM restart failed: ",error);
        eventually([&]{return service_host::getState(state,error)&&state.reachable&&state.proxyRunning&&portOpen(profile.proxy.socksPort);},30000,"Persisted boot option did not start GOST after fresh SCM process startup");
        require(service_host::loadProfile(loaded,error)&&loaded.proxyAutoStart&&loaded.proxy.password==profile.proxy.password&&loaded.mt.secret==telegram.secret&&!loaded.mtAutoStart,"Profile did not survive SCM restart");
        socksRoundTrip(profile.proxy,echo.port);passed("fresh SCM process startup honors persisted boot flags and protected profile");
        requireApi(service_host::uninstall(error),"Uninstall failed: ",error);installedByThisTest=false;
        eventually([&]{return service_host::getState(state,error)&&!state.installed;},20000,"SCM service remains after uninstall");
        require(!portOpen(profile.proxy.socksPort)&&!portOpen(profile.proxy.httpPort),"Uninstall left listeners open");
        require(exists(dataRoot+L"\\profile.dpapi"),"Uninstall unexpectedly deleted retained protected profile");
        passed("uninstall stops owned resources and retains protected data");
        std::cout<<"WINDOWS_SERVICE_INTEGRATION_PASSED groups="<<groups<<"\n"<<std::flush;return 0;
    }catch(const std::exception& failure){
        std::cerr<<"FAIL: "<<failure.what()<<"\n";
        if(installedByThisTest){std::string cleanup;service_host::stopService(cleanup);if(!service_host::uninstall(cleanup))std::cerr<<"Test-owned service cleanup failed: "<<cleanup<<"\n";}
        return 1;
    }
}
