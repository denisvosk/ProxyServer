#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <windows.h>
#include <winsvc.h>
#include <sddl.h>
#include <aclapi.h>
#include <shlobj.h>
#include <shellapi.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include "service_host.h"
#include "service_codec.h"
#include "service_firewall.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <deque>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <utility>

namespace service_host {
namespace {
using codec::Bytes;
const wchar_t ServiceName[]=L"ProxyServer21";
const wchar_t PipeName[]=L"\\\\.\\pipe\\ProxyServer21.Control.v1";
const wchar_t EngineMutexName[]=L"Global\\ProxyServer21.EngineOwner.v1";
const wchar_t ManagementMutexName[]=L"Global\\ProxyServer21.Management.v1";
const wchar_t DirectorySddl[]=L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const wchar_t ObjectSddl[]=L"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)";
const std::size_t MaxFile=2*1024*1024;
const DWORD IoTimeout=3000;
const DWORD CommandTimeout=20000;
enum Operation : std::uint32_t { Query=1,ReadProfile=2,WriteProxy=3,WriteTelegram=4,ProxyOn=5,ProxyOff=6,TelegramOn=7,TelegramOff=8 };

struct Handle {
    HANDLE value=INVALID_HANDLE_VALUE;
    Handle(){}
    explicit Handle(HANDLE h):value(h){}
    ~Handle(){reset();}
    bool valid() const{return value&&value!=INVALID_HANDLE_VALUE;}
    void reset(HANDLE h=INVALID_HANDLE_VALUE){if(valid())CloseHandle(value);value=h;}
    HANDLE release(){HANDLE h=value;value=INVALID_HANDLE_VALUE;return h;}
    Handle(Handle&& other) noexcept:value(other.release()){}
    Handle& operator=(Handle&& other) noexcept{if(this!=&other)reset(other.release());return *this;}
    Handle(const Handle&)=delete;Handle& operator=(const Handle&)=delete;
};
struct ScHandle {
    SC_HANDLE value=nullptr;
    ~ScHandle(){if(value)CloseServiceHandle(value);}
    ScHandle(){};ScHandle(const ScHandle&)=delete;ScHandle& operator=(const ScHandle&)=delete;
};
struct Descriptor {
    PSECURITY_DESCRIPTOR value=nullptr;
    SECURITY_ATTRIBUTES attributes={};
    ~Descriptor(){if(value)LocalFree(value);}
    bool make(const wchar_t* sddl){
        if(!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,SDDL_REVISION_1,&value,nullptr))return false;
        attributes.nLength=sizeof(attributes);attributes.lpSecurityDescriptor=value;attributes.bInheritHandle=FALSE;return true;
    }
};
std::string winError(const char* stage,DWORD code=GetLastError()) {
    return std::string(stage)+" (Windows "+std::to_string(code)+").";
}
bool fail(std::string& error,const std::string& message){error=message;return false;}
std::wstring wide(const std::string& value) {
    if(value.empty())return L"";
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0);
    if(n<=0)return L"";
    std::wstring out(static_cast<std::size_t>(n),L'\0');
    if(!MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),&out[0],n))return L"";
    return out;
}
std::string narrow(const std::wstring& value) {
    if(value.empty())return "";
    int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),nullptr,0,nullptr,nullptr);
    if(n<=0)return "";
    std::string out(static_cast<std::size_t>(n),'\0');
    if(!WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,value.data(),static_cast<int>(value.size()),&out[0],n,nullptr,nullptr))return "";
    return out;
}
bool same(const std::wstring& a,const std::wstring& b){return _wcsicmp(a.c_str(),b.c_str())==0;}
std::wstring nativePath(const std::wstring& path){return L"\\\\?\\"+path;}
bool canonical(const std::wstring& path,std::wstring& out,std::string& error) {
    if(path.size()<3||path.size()>32000||path.find(L'\0')!=std::wstring::npos||path[1]!=L':'||
       !((path[0]>=L'A'&&path[0]<=L'Z')||(path[0]>=L'a'&&path[0]<=L'z'))||
       (path[2]!=L'\\'&&path[2]!=L'/')||path.find(L':',2)!=std::wstring::npos||
       path.find_first_of(L"\r\n\"*?<>|")!=std::wstring::npos)
        return fail(error,"A local absolute drive path is required; network and device paths are not accepted.");
    std::vector<wchar_t> buffer(32768);
    DWORD n=GetFullPathNameW(path.c_str(),static_cast<DWORD>(buffer.size()),buffer.data(),nullptr);
    if(!n||n>=buffer.size())return fail(error,winError("Cannot normalize a local path"));
    out.assign(buffer.data(),n);std::replace(out.begin(),out.end(),L'/',L'\\');
    while(out.size()>3&&out.back()==L'\\')out.pop_back();
    return true;
}
bool noReparseAncestors(const std::wstring& path,bool includeLeaf,std::string& error) {
    const std::size_t end=includeLeaf?path.size():path.find_last_of(L'\\');
    for(std::size_t i=3;i<=end;++i) {
        if(i!=end&&path[i]!=L'\\')continue;
        const std::wstring part=path.substr(0,i);
        DWORD attr=GetFileAttributesW(nativePath(part).c_str());
        if(attr==INVALID_FILE_ATTRIBUTES)return fail(error,winError("Cannot inspect the local path"));
        if(attr&FILE_ATTRIBUTE_REPARSE_POINT)return fail(error,"Service files cannot use a junction, symbolic link or another reparse point.");
    }
    return true;
}
bool sidIs(PSID sid,WELL_KNOWN_SID_TYPE type) {
    BYTE expected[SECURITY_MAX_SID_SIZE]={};DWORD size=sizeof(expected);
    return sid&&CreateWellKnownSid(type,nullptr,expected,&size)&&EqualSid(sid,expected);
}
bool protectedAcl(HANDLE handle,std::string& error) {
    PSECURITY_DESCRIPTOR descriptor=nullptr;PSID owner=nullptr;PACL acl=nullptr;
    DWORD code=GetSecurityInfo(handle,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&owner,nullptr,&acl,nullptr,&descriptor);
    if(code!=ERROR_SUCCESS)return fail(error,winError("Cannot inspect service file permissions",code));
    struct Free {PSECURITY_DESCRIPTOR p;~Free(){LocalFree(p);}} cleanup{descriptor};
    SECURITY_DESCRIPTOR_CONTROL control=0;DWORD revision=0;
    if(!GetSecurityDescriptorControl(descriptor,&control,&revision)||!acl||!(control&SE_DACL_PROTECTED)||
       !(sidIs(owner,WinLocalSystemSid)||sidIs(owner,WinBuiltinAdministratorsSid)))
        return fail(error,"Service storage is not protected for SYSTEM and Administrators. Existing unsafe directories are never adopted.");
    bool system=false,administrators=false;
    for(DWORD i=0;i<acl->AceCount;++i) {
        void* raw=nullptr;if(!GetAce(acl,i,&raw))return fail(error,"Cannot read the service storage ACL.");
        ACE_HEADER* header=static_cast<ACE_HEADER*>(raw);
        if(header->AceType!=ACCESS_ALLOWED_ACE_TYPE)return fail(error,"Unexpected access-control entry in service storage.");
        ACCESS_ALLOWED_ACE* ace=static_cast<ACCESS_ALLOWED_ACE*>(raw);PSID sid=&ace->SidStart;
        const bool sy=sidIs(sid,WinLocalSystemSid),ba=sidIs(sid,WinBuiltinAdministratorsSid);
        if(!sy&&!ba)return fail(error,"Service storage grants access to an account outside SYSTEM and Administrators.");
        if(!(ace->Header.AceFlags&INHERIT_ONLY_ACE)&&((ace->Mask&FILE_ALL_ACCESS)==FILE_ALL_ACCESS||(ace->Mask&GENERIC_ALL))) {
            system=system||sy;administrators=administrators||ba;
        }
    }
    if(!system||!administrators)return fail(error,"Service storage does not grant the required SYSTEM and Administrators access.");
    return true;
}
bool directory(const std::wstring& path,bool create,std::vector<Handle>& locks,std::string& error) {
    if(!noReparseAncestors(path,false,error))return false;
    if(create) {
        Descriptor descriptor;if(!descriptor.make(DirectorySddl))return fail(error,winError("Cannot create a protected directory ACL"));
        if(!CreateDirectoryW(nativePath(path).c_str(),&descriptor.attributes)&&GetLastError()!=ERROR_ALREADY_EXISTS)
            return fail(error,winError("Cannot create protected service storage"));
    }
    Handle h(CreateFileW(nativePath(path).c_str(),FILE_READ_ATTRIBUTES|READ_CONTROL,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    if(!h.valid())return fail(error,winError("Cannot open protected service storage"));
    BY_HANDLE_FILE_INFORMATION info={};
    if(!GetFileInformationByHandle(h.value,&info)||!(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)||(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT))
        return fail(error,"Service storage must be a normal directory, not a reparse point.");
    if(!protectedAcl(h.value,error))return false;
    locks.push_back(std::move(h));return true;
}
struct Paths {std::wstring root,data,install;};
bool paths(Paths& out,std::string& error) {
    PWSTR programs=nullptr,data=nullptr;
    HRESULT hr=SHGetKnownFolderPath(FOLDERID_ProgramFilesX64,0,nullptr,&programs);
    if(FAILED(hr))hr=SHGetKnownFolderPath(FOLDERID_ProgramFiles,0,nullptr,&programs);
    if(FAILED(hr))return fail(error,"Cannot locate the protected Program Files directory.");
    hr=SHGetKnownFolderPath(FOLDERID_ProgramData,0,nullptr,&data);
    if(FAILED(hr)){CoTaskMemFree(programs);return fail(error,"Cannot locate the ProgramData directory.");}
    std::wstring programPath=programs,dataPath=data;CoTaskMemFree(programs);CoTaskMemFree(data);
    if(!canonical(programPath+L"\\ProxyServer21",out.root,error)||!canonical(dataPath+L"\\ProxyServer21",out.data,error))return false;
    return true;
}
std::wstring executablePath() {
    std::vector<wchar_t> path(32768);DWORD n=GetModuleFileNameW(nullptr,path.data(),static_cast<DWORD>(path.size()));
    return n&&n<path.size()?std::wstring(path.data(),n):L"";
}
bool randomName(std::wstring& name,std::string& error) {
    unsigned char bytes[16]={};if(BCryptGenRandom(nullptr,bytes,sizeof(bytes),BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0)
        return fail(error,"Windows could not generate a secure installation identifier.");
    static const wchar_t hex[]=L"0123456789abcdef";name.clear();
    for(unsigned char b:bytes){name+=hex[b>>4];name+=hex[b&15];}SecureZeroMemory(bytes,sizeof(bytes));return true;
}
bool readFile(const std::wstring& path,Bytes& bytes,std::size_t maximum,bool requireProtection,std::string& error) {
    if(!noReparseAncestors(path,true,error))return false;
    Handle h(CreateFileW(nativePath(path).c_str(),GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_SEQUENTIAL_SCAN,nullptr));
    if(!h.valid())return fail(error,winError("Cannot read the selected local file"));
    BY_HANDLE_FILE_INFORMATION info={};LARGE_INTEGER size={};
    if(!GetFileInformationByHandle(h.value,&info)||!GetFileSizeEx(h.value,&size)||size.QuadPart<0||
       static_cast<unsigned long long>(size.QuadPart)>maximum||(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))||info.nNumberOfLinks!=1)
        return fail(error,"Selected file is too large, is a link, or is not an ordinary local file.");
    if(requireProtection&&!protectedAcl(h.value,error))return false;
    Bytes result(static_cast<std::size_t>(size.QuadPart));std::size_t offset=0;
    while(offset<result.size()) {
        DWORD got=0;if(!ReadFile(h.value,result.data()+offset,static_cast<DWORD>((std::min)(result.size()-offset,std::size_t(65536))),&got,nullptr)||!got)
            {codec::erase(result);return fail(error,winError("Cannot finish reading the local file"));}
        offset+=got;
    }
    bytes.swap(result);codec::erase(result);return true;
}
bool writeNew(const std::wstring& path,const Bytes& bytes,std::string& error) {
    Descriptor descriptor;if(!descriptor.make(DirectorySddl))return fail(error,winError("Cannot create the protected file ACL"));
    Handle h(CreateFileW(nativePath(path).c_str(),GENERIC_WRITE,0,&descriptor.attributes,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_WRITE_THROUGH,nullptr));
    if(!h.valid())return fail(error,winError("Cannot create a new protected service file"));
    std::size_t offset=0;bool ok=true;
    while(offset<bytes.size()) {
        DWORD written=0;if(!WriteFile(h.value,bytes.data()+offset,static_cast<DWORD>((std::min)(bytes.size()-offset,std::size_t(65536))),&written,nullptr)||!written){ok=false;break;}
        offset+=written;
    }
    if(ok)ok=FlushFileBuffers(h.value)!=FALSE;
    const DWORD code=ok?ERROR_SUCCESS:GetLastError();h.reset();
    if(!ok){DeleteFileW(nativePath(path).c_str());return fail(error,winError("Cannot finish writing a protected service file",code));}
    return true;
}
bool readProfileFile(const Paths& locations,Profile& profile,std::string& error) {
    std::vector<Handle> locks;if(!directory(locations.data,false,locks,error))return false;
    Bytes encrypted;if(!readFile(locations.data+L"\\profile.dpapi",encrypted,codec::MaxPayload+16384,true,error))return false;
    DATA_BLOB input={static_cast<DWORD>(encrypted.size()),encrypted.empty()?nullptr:encrypted.data()},output={};
    if(!CryptUnprotectData(&input,nullptr,nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&output))
        return fail(error,winError("Cannot decrypt this machine's service profile"));
    bool ok=false;
    if(output.cbData<=codec::MaxPayload) {
        Bytes plain(output.pbData,output.pbData+output.cbData);ok=codec::decodeProfile(plain,profile);codec::erase(plain);
    }
    SecureZeroMemory(output.pbData,output.cbData);LocalFree(output.pbData);
    if(!ok)return fail(error,"The protected profile is damaged or uses an unsupported schema version.");
    return true;
}
bool writeProfileFile(const Paths& locations,const Profile& profile,std::string& error) {
    std::vector<Handle> locks;if(!directory(locations.data,true,locks,error))return false;
    const std::wstring target=locations.data+L"\\profile.dpapi";
    if(GetFileAttributesW(nativePath(target).c_str())!=INVALID_FILE_ATTRIBUTES) {
        Bytes previous;if(!readFile(target,previous,codec::MaxPayload+16384,true,error))return false;
    }
    Bytes plain;if(!codec::encodeProfile(profile,plain))return fail(error,"The service profile exceeds its format limits.");
    DATA_BLOB input={static_cast<DWORD>(plain.size()),plain.data()},output={};
    const bool encrypted=CryptProtectData(&input,L"ProxyServer21 service profile v1",nullptr,nullptr,nullptr,CRYPTPROTECT_LOCAL_MACHINE|CRYPTPROTECT_UI_FORBIDDEN,&output)!=FALSE;
    const DWORD code=encrypted?ERROR_SUCCESS:GetLastError();codec::erase(plain);
    if(!encrypted)return fail(error,winError("Cannot protect the service profile",code));
    Bytes blob(output.pbData,output.pbData+output.cbData);SecureZeroMemory(output.pbData,output.cbData);LocalFree(output.pbData);
    std::wstring suffix;if(!randomName(suffix,error))return false;
    const std::wstring temporary=locations.data+L"\\profile-"+suffix+L".tmp";
    if(!writeNew(temporary,blob,error))return false;
    if(!MoveFileExW(nativePath(temporary).c_str(),nativePath(target).c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)) {
        const DWORD moveError=GetLastError();DeleteFileW(nativePath(temporary).c_str());return fail(error,winError("Cannot atomically replace the protected service profile",moveError));
    }
    return true;
}

bool hasProxy(const Profile& p){return p.proxyAutoStart||!p.proxy.user.empty()||!p.proxy.password.empty();}
bool hasTelegram(const Profile& p){return p.mtAutoStart||!p.mt.secret.empty();}
std::string settingError(const std::string& code) {
    if(code=="USER")return u8"Укажите корректный логин прокси.";
    if(code=="PASSWORD")return u8"Пароль прокси должен содержать 8–255 печатных ASCII-символов без пробелов.";
    if(code=="PORTS")return u8"Включённые входы прокси должны использовать разные порты от 1 до 65535.";
    if(code=="PROTOCOLS")return u8"Включите хотя бы один вход прокси или локальный DNS.";
    if(code=="TLS")return u8"Укажите абсолютные пути к PEM-сертификату и закрытому ключу.";
    if(code.compare(0,3,"MT_")==0)return u8"Проверьте порт, адрес и секрет MTProto; секрет должен соответствовать выбранному домену.";
    return u8"Проверьте настройки перед сохранением профиля службы. Код: "+code;
}
bool validateProfile(const Profile& p,std::string& error) {
    std::string reason;
    if(hasProxy(p)&&!proxy::validate(p.proxy,reason))return fail(error,settingError(reason));
    if(hasTelegram(p)&&!mtproto::validate(p.mt,reason))return fail(error,settingError(reason));
    if(hasTelegram(p)) {
        std::string domain;if(!mtproto::secretDomain(p.mt.secret,domain))return fail(error,settingError("MT_SECRET"));
        if(!p.tlsDomain.empty()&&_stricmp(domain.c_str(),p.tlsDomain.c_str())!=0)
            return fail(error,u8"Домен MTProto не совпадает с доменом в секрете. Создайте соответствующий секрет.");
    }
    if(p.proxyAutoStart&&p.mtAutoStart&&
       (p.proxy.bindAddress=="0.0.0.0"||p.mt.bindAddress=="0.0.0.0"||p.proxy.bindAddress==p.mt.bindAddress)) {
        const bool enabled[]={p.proxy.enableSocks,p.proxy.enableHttp,p.proxy.enableChainSocks,p.proxy.enableChainHttp,p.proxy.enableHttps,p.proxy.enableSocksTls,p.proxy.enableDns};
        const unsigned short ports[]={p.proxy.socksPort,p.proxy.httpPort,p.proxy.chainSocksPort,p.proxy.chainHttpPort,p.proxy.httpsPort,p.proxy.socksTlsPort,p.proxy.dnsPort};
        for(unsigned i=0;i<7;++i)if(enabled[i]&&ports[i]==p.mt.listenPort)
            return fail(error,u8"MTProto и другой автоматически запускаемый вход используют один TCP-порт. Выберите разные порты.");
    }
    return true;
}
bool importTls(const Paths& locations,Profile& profile,std::string& error) {
    if(!hasProxy(profile)||!(profile.proxy.enableHttps||profile.proxy.enableSocksTls))return true;
    std::wstring certificate,key;
    if(!canonical(wide(profile.proxy.tlsCertFile),certificate,error)||!canonical(wide(profile.proxy.tlsKeyFile),key,error))return false;
    Bytes certBytes,keyBytes;
    if(!readFile(certificate,certBytes,MaxFile,false,error)||!readFile(key,keyBytes,MaxFile,false,error)){codec::erase(keyBytes);return false;}
    if(certBytes.empty()||keyBytes.empty()){codec::erase(keyBytes);return fail(error,u8"TLS-сертификат и закрытый ключ не должны быть пустыми.");}
    std::wstring suffix;if(!randomName(suffix,error)){codec::erase(keyBytes);return false;}
    std::vector<Handle> locks;
    const std::wstring leaf=locations.data+L"\\tls-"+suffix;
    if(!directory(locations.data,true,locks,error)||!directory(leaf,true,locks,error)){codec::erase(keyBytes);return false;}
    const bool ok=writeNew(leaf+L"\\cert.pem",certBytes,error)&&writeNew(leaf+L"\\key.pem",keyBytes,error);
    codec::erase(keyBytes);
    if(!ok)return false;
    profile.proxy.tlsCertFile=narrow(leaf+L"\\cert.pem");profile.proxy.tlsKeyFile=narrow(leaf+L"\\key.pem");return true;
}
bool applyFirewall(const Paths& locations,const Profile& profile,std::string& error) {
    if(!profile.manageFirewall)return true;
    return service_firewall::apply(profile.proxy,profile.mt,locations.install,hasTelegram(profile),error);
}
bool commitProfile(const Paths& locations,const Profile& previous,Profile& next,std::string& error) {
    if(!validateProfile(next,error)||!importTls(locations,next,error)||!applyFirewall(locations,next,error))return false;
    if(writeProfileFile(locations,next,error))return true;
    if(next.manageFirewall) {
        std::string rollback;
        const bool restored=previous.manageFirewall?applyFirewall(locations,previous,rollback):service_firewall::remove(locations.install,rollback);
        if(!restored)error+=u8" Восстановление прежних правил брандмауэра тоже не выполнено: "+rollback;
    }
    return false;
}
bool installedPath(const std::wstring& commandLine,Paths& locations,std::string& error) {
    int count=0;LPWSTR* args=CommandLineToArgvW(commandLine.c_str(),&count);
    if(!args)return fail(error,winError("Cannot inspect the registered service command"));
    std::wstring executable=count>0?args[0]:L"";const bool arguments=count==2&&wcscmp(args[1],L"--service")==0;LocalFree(args);
    std::wstring full;if(!arguments||!canonical(executable,full,error))return fail(error,"The service name belongs to an unexpected executable or command. It will not be modified.");
    const std::wstring prefix=locations.root+L"\\host-",suffix=L"\\ProxyServer.exe";
    if(full.size()!=prefix.size()+32+suffix.size()||_wcsnicmp(full.c_str(),prefix.c_str(),prefix.size())!=0||
       !same(full.substr(full.size()-suffix.size()),suffix))return fail(error,"The registered service is outside this application's protected installation directory.");
    for(std::size_t i=prefix.size();i<prefix.size()+32;++i)if(!((full[i]>=L'0'&&full[i]<=L'9')||(full[i]>=L'a'&&full[i]<=L'f')||(full[i]>=L'A'&&full[i]<=L'F')))
        return fail(error,"The registered installation identifier is invalid.");
    locations.install=full.substr(0,full.size()-suffix.size());return true;
}
bool lookup(State& state,Paths& locations,ScHandle& scm,ScHandle& service,DWORD access,std::string& error,DWORD* pid=nullptr) {
    if(!paths(locations,error))return false;
    state.dataDir=locations.data;
    scm.value=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CONNECT);
    if(!scm.value)return fail(error,winError("Cannot access the local Windows service manager"));
    service.value=OpenServiceW(scm.value,ServiceName,SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS|access);
    if(!service.value) {
        if(GetLastError()==ERROR_SERVICE_DOES_NOT_EXIST){state.installed=false;state.scmState=0;return true;}
        return fail(error,winError("Cannot open the local proxy service"));
    }
    state.installed=true;
    SERVICE_STATUS_PROCESS status={};DWORD needed=0;
    if(!QueryServiceStatusEx(service.value,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&status),sizeof(status),&needed))
        return fail(error,winError("Cannot query the service state"));
    state.scmState=status.dwCurrentState;if(pid)*pid=status.dwProcessId;
    QueryServiceConfigW(service.value,nullptr,0,&needed);
    if(!needed||needed>65536)return fail(error,"The service configuration size is invalid.");
    std::vector<BYTE> bytes(needed);auto config=reinterpret_cast<QUERY_SERVICE_CONFIGW*>(bytes.data());
    if(!QueryServiceConfigW(service.value,config,needed,&needed))return fail(error,winError("Cannot read the registered service configuration"));
    if(config->dwServiceType!=SERVICE_WIN32_OWN_PROCESS||!config->lpServiceStartName||
       !(same(config->lpServiceStartName,L"LocalSystem")||same(config->lpServiceStartName,L"NT AUTHORITY\\SYSTEM")))
        return fail(error,"The existing service has an unexpected type or account and will not be modified.");
    if(!installedPath(config->lpBinaryPathName,locations,error))return false;
    state.installDir=locations.install;return true;
}
bool verifyInstallation(const Paths& locations,std::vector<Handle>& locks,std::string& error) {
    if(!directory(locations.root,false,locks,error)||!directory(locations.install,false,locks,error)||
       !directory(locations.install+L"\\components",false,locks,error))return false;
    const wchar_t* files[]={L"\\ProxyServer.exe",L"\\components\\gost.exe",L"\\components\\mtg.exe",L"\\components\\proxy-cert.exe"};
    for(const wchar_t* file:files) {
        const std::wstring path=locations.install+file;
        Handle h(CreateFileW(nativePath(path).c_str(),GENERIC_READ|READ_CONTROL,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
        BY_HANDLE_FILE_INFORMATION info={};
        if(!h.valid()||!GetFileInformationByHandle(h.value,&info)||(info.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))||info.nNumberOfLinks!=1)
            return fail(error,"A protected service executable is missing, is a link, or is not a normal file.");
        if(!protectedAcl(h.value,error))return false;
        locks.push_back(std::move(h));
    }
    return true;
}
struct ManagementLock {
    Handle handle;bool owned=false;
    ~ManagementLock(){if(owned)ReleaseMutex(handle.value);}
    bool acquire(std::string& error) {
        Descriptor descriptor;if(!descriptor.make(ObjectSddl))return fail(error,winError("Cannot create the service management ACL"));
        handle.reset(CreateMutexW(&descriptor.attributes,FALSE,ManagementMutexName));
        if(!handle.valid())return fail(error,winError("Cannot open the service management lock"));
        DWORD result=WaitForSingleObject(handle.value,2500);owned=result==WAIT_OBJECT_0||result==WAIT_ABANDONED;
        return owned||fail(error,u8"Уже выполняется другая операция со службой. Дождитесь её завершения.");
    }
};
bool waitService(SC_HANDLE service,DWORD desired,std::string& error) {
    const ULONGLONG deadline=GetTickCount64()+CommandTimeout;
    while(GetTickCount64()<deadline) {
        SERVICE_STATUS_PROCESS status={};DWORD needed=0;
        if(!QueryServiceStatusEx(service,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&status),sizeof(status),&needed))return fail(error,winError("Cannot query the service transition"));
        if(status.dwCurrentState==desired)return true;
        if(desired==SERVICE_RUNNING&&status.dwCurrentState==SERVICE_STOPPED)
            return fail(error,u8"Служба завершилась при запуске. Код Windows: "+std::to_string(status.dwWin32ExitCode)+u8". Проверьте защищённые файлы установки и журнал Windows.");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return fail(error,u8"Windows не завершила операцию со службой за 20 секунд. Проверьте её текущее состояние перед повтором.");
}

// Cancelled overlapped operations retain their own buffers until Windows has
// completed them. This avoids freeing an OVERLAPPED or buffer after a timeout.
struct PendingIo {
    OVERLAPPED overlapped={};Handle event;Bytes buffer;
    explicit PendingIo(std::size_t size):event(CreateEventW(nullptr,TRUE,FALSE,nullptr)),buffer(size){overlapped.hEvent=event.value;}
    ~PendingIo(){codec::erase(buffer);}
};
std::vector<std::shared_ptr<PendingIo>>& retiredIo(){static auto* values=new std::vector<std::shared_ptr<PendingIo>>;return *values;}
void collectIo() {
    auto& retired=retiredIo();retired.erase(std::remove_if(retired.begin(),retired.end(),[](const std::shared_ptr<PendingIo>& p){return WaitForSingleObject(p->event.value,0)==WAIT_OBJECT_0;}),retired.end());
}
void cancelIo(HANDLE pipe,const std::shared_ptr<PendingIo>& operation) {
    CancelIoEx(pipe,&operation->overlapped);
    if(WaitForSingleObject(operation->event.value,100)!=WAIT_OBJECT_0)retiredIo().push_back(operation);
}
bool transfer(HANDLE pipe,Bytes& bytes,bool writing,ULONGLONG deadline,HANDLE stop,std::string& error) {
    std::size_t offset=0;
    while(offset<bytes.size()) {
        if((stop&&WaitForSingleObject(stop,0)==WAIT_OBJECT_0)||GetTickCount64()>=deadline)
            return fail(error,u8"Обмен данными со службой отменён или истекло время ожидания.");
        collectIo();if(retiredIo().size()>=8)return fail(error,"Too many cancelled local IPC operations are still pending.");
        auto operation=std::make_shared<PendingIo>((std::min)(bytes.size()-offset,std::size_t(65536)));
        if(!operation->event.valid())return fail(error,winError("Cannot create the IPC completion event"));
        if(writing)std::copy(bytes.begin()+offset,bytes.begin()+offset+operation->buffer.size(),operation->buffer.begin());
        DWORD completed=0;
        BOOL ok=writing?WriteFile(pipe,operation->buffer.data(),static_cast<DWORD>(operation->buffer.size()),&completed,&operation->overlapped):
                        ReadFile(pipe,operation->buffer.data(),static_cast<DWORD>(operation->buffer.size()),&completed,&operation->overlapped);
        if(!ok) {
            const DWORD code=GetLastError();if(code!=ERROR_IO_PENDING)return fail(error,winError("Local service connection closed",code));
            const ULONGLONG now=GetTickCount64();DWORD left=now<deadline?static_cast<DWORD>(deadline-now):0;
            HANDLE events[]={operation->event.value,stop};DWORD result=WaitForMultipleObjects(stop?2:1,events,FALSE,left);
            if(result!=WAIT_OBJECT_0) {cancelIo(pipe,operation);return fail(error,u8"Служба не ответила в отведённое время или операция была отменена.");}
            if(!GetOverlappedResult(pipe,&operation->overlapped,&completed,FALSE))return fail(error,winError("Local service I/O failed"));
        }
        if(!completed||completed>operation->buffer.size())return fail(error,"The local service connection ended unexpectedly.");
        if(!writing)std::copy(operation->buffer.begin(),operation->buffer.begin()+completed,bytes.begin()+offset);
        codec::erase(operation->buffer);offset+=completed;
        if(GetTickCount64()>deadline)return fail(error,u8"Истекло время обмена данными со службой.");
    }
    return true;
}
bool sendFrame(HANDLE pipe,std::uint32_t operation,const Bytes& payload,ULONGLONG deadline,HANDLE stop,std::string& error) {
    if(payload.size()>codec::MaxPayload)return fail(error,"Local IPC message exceeds its size limit.");
    codec::Writer header;header.u32(codec::WireMagic);header.u32(codec::Version);header.u32(operation);header.u32(static_cast<std::uint32_t>(payload.size()));
    Bytes copy=payload;bool ok=transfer(pipe,header.data,true,deadline,stop,error)&&transfer(pipe,copy,true,deadline,stop,error);codec::erase(copy);return ok;
}
bool readHeader(HANDLE pipe,std::uint32_t& operation,std::uint32_t& size,ULONGLONG deadline,HANDLE stop,std::string& error) {
    Bytes header(16);if(!transfer(pipe,header,false,deadline,stop,error))return false;
    codec::Reader reader(header);std::uint32_t magic=0,version=0;reader.u32(magic);reader.u32(version);reader.u32(operation);reader.u32(size);
    if(!reader.done()||magic!=codec::WireMagic||version!=codec::Version||size>codec::MaxPayload)return fail(error,"Unsupported or oversized local service protocol message.");
    return true;
}
bool clientIsAdministrator(HANDLE pipe) {
    if(!ImpersonateNamedPipeClient(pipe))return false;
    BYTE sid[SECURITY_MAX_SID_SIZE]={};DWORD size=sizeof(sid);BOOL member=FALSE;
    bool allowed=CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,sid,&size)&&CheckTokenMembership(nullptr,sid,&member)&&member;
    if(!allowed){size=sizeof(sid);member=FALSE;allowed=CreateWellKnownSid(WinLocalSystemSid,nullptr,sid,&size)&&CheckTokenMembership(nullptr,sid,&member)&&member;}
    if(!RevertToSelf())TerminateProcess(GetCurrentProcess(),ERROR_ACCESS_DENIED);
    return allowed;
}
bool trustedPipeServer(HANDLE pipe,const Paths& locations,DWORD expectedPid,std::string& error) {
    ULONG pid=0;if(!expectedPid||!GetNamedPipeServerProcessId(pipe,&pid)||pid!=expectedPid)return fail(error,"The local pipe does not belong to the registered service. No profile was sent.");
    Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid));
    if(!process.valid())return fail(error,winError("Cannot verify the service process"));
    std::vector<wchar_t> name(32768);DWORD size=static_cast<DWORD>(name.size());
    if(!QueryFullProcessImageNameW(process.value,0,name.data(),&size)||!same(std::wstring(name.data(),size),locations.install+L"\\ProxyServer.exe"))
        return fail(error,"The local pipe server has an unexpected executable path. No profile was sent.");
    Handle token;HANDLE raw=nullptr;if(!OpenProcessToken(process.value,TOKEN_QUERY,&raw))return fail(error,winError("Cannot verify the service account"));token.reset(raw);
    DWORD required=0;GetTokenInformation(token.value,TokenUser,nullptr,0,&required);
    if(!required||required>4096)return fail(error,"Unexpected service security token.");
    std::vector<BYTE> data(required);
    if(!GetTokenInformation(token.value,TokenUser,data.data(),required,&required)||!sidIs(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid,WinLocalSystemSid))
        return fail(error,"The local service is not running as SYSTEM. No profile was sent.");
    return true;
}
bool request(std::uint32_t operation,const Bytes& input,Bytes& output,std::string& error) {
    State state;Paths locations;ScHandle scm,service;DWORD pid=0;
    if(!lookup(state,locations,scm,service,0,error,&pid))return false;
    if(!state.installed||state.scmState!=SERVICE_RUNNING)return fail(error,u8"Служба остановлена. Сначала запустите службу.");
    const ULONGLONG deadline=GetTickCount64()+(operation==Query?IoTimeout:CommandTimeout);
    Handle pipe;
    for(;;) {
        pipe.reset(CreateFileW(PipeName,GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION,nullptr));
        if(pipe.valid())break;
        DWORD code=GetLastError();if((code!=ERROR_PIPE_BUSY&&code!=ERROR_FILE_NOT_FOUND)||GetTickCount64()>=deadline)return fail(error,winError("Cannot connect to the local service",code));
        WaitNamedPipeW(PipeName,100);
    }
    // Verify before transmitting any credential-bearing profile bytes.
    SERVICE_STATUS_PROCESS fresh={};DWORD needed=0;
    if(!QueryServiceStatusEx(service.value,SC_STATUS_PROCESS_INFO,reinterpret_cast<BYTE*>(&fresh),sizeof(fresh),&needed)||fresh.dwCurrentState!=SERVICE_RUNNING||fresh.dwProcessId!=pid)
        return fail(error,"The service changed while connecting; retry the operation.");
    if(!trustedPipeServer(pipe.value,locations,pid,error)||!sendFrame(pipe.value,operation,input,deadline,nullptr,error))return false;
    std::uint32_t replyOperation=0,size=0;
    if(!readHeader(pipe.value,replyOperation,size,deadline,nullptr,error)||replyOperation!=(operation|0x80000000u))return fail(error,"Invalid reply from the local service.");
    Bytes response(size);if(!transfer(pipe.value,response,false,deadline,nullptr,error))return false;
    // DisconnectNamedPipe discards unread data. Acknowledge only after the
    // complete response was consumed, including an error response.
    Bytes acknowledgment(1,0xA5);
    if(!transfer(pipe.value,acknowledgment,true,deadline,nullptr,error)){codec::erase(response);return false;}
    codec::Reader reader(response);bool success=false;std::string message;reader.boolean(success);reader.text(message);reader.bytes(output);
    const bool valid=reader.done();codec::erase(response);
    if(!valid)return fail(error,"The service response is malformed.");
    if(!success)return fail(error,message.empty()?"Service operation failed.":message);
    error.clear();return true;
}

struct Recovery {
    bool desired=false,wasRunning=false;
    unsigned failures=0;
    ULONGLONG next=0,started=0;
    std::uint64_t restarts=0;
    std::string error;
};
struct Runtime {
    Paths locations;Profile profile;proxy::Server proxy;mtproto::Controller mt;
    Recovery proxyRecovery,mtRecovery;
    std::deque<proxy::Event> events;std::uint64_t nextEvent=1,proxyCursor=0;
    std::string error;
    explicit Runtime(const Paths& p):locations(p) {
        FILETIME time={};GetSystemTimeAsFileTime(&time);ULARGE_INTEGER value={};value.LowPart=time.dwLowDateTime;value.HighPart=time.dwHighDateTime;nextEvent=value.QuadPart;
    }
    ~Runtime(){proxy.stop();mt.stop();codec::erase(profile);}
    std::string safe(std::string text) const {
        const std::string* secrets[]={&profile.proxy.password,&profile.proxy.upstreamPassword,&profile.mt.secret};
        for(const auto* secret:secrets)if(!secret->empty()) {
            std::size_t at=0;while((at=text.find(*secret,at))!=std::string::npos){text.replace(at,secret->size(),"[hidden]");at+=8;}
        }
        for(char& c:text)if(static_cast<unsigned char>(c)<32)c=' ';
        if(text.size()>2048) {
            std::size_t end=2048;while(end&&(static_cast<unsigned char>(text[end])&0xC0)==0x80)--end;
            text.resize(end);
        }
        return text;
    }
    void log(const std::string& level,const std::string& text) {
        proxy::Event event;event.id=nextEvent++;event.level=level;event.message=safe(text);
        if(event.message.size()>1024) {
            std::size_t end=1024;while(end&&(static_cast<unsigned char>(event.message[end])&0xC0)==0x80)--end;
            event.message.resize(end);
        }
        SYSTEMTIME time={};GetLocalTime(&time);char clock[16]={};snprintf(clock,sizeof(clock),"%02u:%02u:%02u",time.wHour,time.wMinute,time.wSecond);event.time=clock;
        events.push_back(event);while(events.size()>200)events.pop_front();
    }
    void collect() {
        for(const auto& event:proxy.events(proxyCursor)){proxyCursor=event.id;log(event.level,"GOST: "+event.message);}
    }
    void failed(Recovery& recovery,const char* component,const std::string& why) {
        recovery.wasRunning=false;recovery.error=safe(why);
        static const unsigned delays[]={2,5,10,30,60};
        if(recovery.failures>=5) {
            recovery.desired=false;recovery.next=0;
            recovery.error=u8"Автовосстановление приостановлено после пяти попыток. Исправьте причину и нажмите «Запуск». "+recovery.error;
            log("error",std::string(component)+": "+recovery.error);return;
        }
        const unsigned delay=delays[recovery.failures++];recovery.next=GetTickCount64()+delay*1000ULL;
        log("warning",std::string(component)+u8": повторный запуск через "+std::to_string(delay)+u8" с. "+recovery.error);
    }
    bool start(bool telegram,bool automatic,std::string& reason) {
        Recovery& recovery=telegram?mtRecovery:proxyRecovery;
        const bool running=telegram?mt.running():proxy.running();if(running){reason.clear();return true;}
        recovery.desired=true;recovery.next=0;
        if(!automatic)recovery.failures=0;
        const bool ok=telegram?mt.start(locations.install+L"\\components\\mtg.exe",profile.mt,reason):proxy.start(profile.proxy,reason);
        if(ok){recovery.wasRunning=true;recovery.started=GetTickCount64();recovery.error.clear();log("info",telegram?u8"MTProto запущен службой.":u8"GOST запущен службой.");}
        else {
            reason=safe(reason);recovery.error=reason;recovery.wasRunning=false;
            if(automatic)failed(recovery,telegram?"MTProto":"GOST",reason);
            else{recovery.desired=false;log("error",std::string(telegram?"MTProto: ":"GOST: ")+reason);}
        }
        return ok;
    }
    void stop(bool telegram) {
        Recovery& recovery=telegram?mtRecovery:proxyRecovery;recovery.desired=false;recovery.wasRunning=false;recovery.next=0;recovery.failures=0;recovery.error.clear();
        if(telegram)mt.stop();else proxy.stop();
        log("info",telegram?u8"MTProto остановлен. До команды запуска или перезапуска службы он останется выключен.":u8"GOST остановлен. До команды запуска или перезапуска службы он останется выключен.");
    }
    void tickOne(bool telegram) {
        Recovery& recovery=telegram?mtRecovery:proxyRecovery;
        if(telegram)mt.poll();
        const bool running=telegram?mt.running():proxy.running();
        const ULONGLONG now=GetTickCount64();
        if(running) {if(now-recovery.started>=60000)recovery.failures=0;return;}
        if(recovery.wasRunning)failed(recovery,telegram?"MTProto":"GOST",telegram?mt.lastError():proxy.lastError());
        if(recovery.desired&&recovery.next&&now>=recovery.next) {++recovery.restarts;std::string reason;start(telegram,true,reason);}
    }
    void tick(){tickOne(false);tickOne(true);collect();collectIo();}
    State snapshot(std::uint64_t after) {
        tick();State state;state.installed=true;state.reachable=true;state.scmState=SERVICE_RUNNING;
        state.proxyRunning=proxy.running();state.mtRunning=mt.running();state.stats=proxy.stats();
        state.proxyError=safe(proxyRecovery.error);state.mtError=safe(mtRecovery.error);state.error=safe(error);
        state.proxyRestarts=proxyRecovery.restarts;state.mtRestarts=mtRecovery.restarts;
        if(!events.empty()&&after>events.back().id)after=0;
        for(const auto& event:events)if(event.id>after)state.events.push_back(event);
        return state;
    }
    bool execute(std::uint32_t operation,const Bytes& input,Bytes& output,std::string& reason) {
        if(operation==Query) {
            codec::Reader reader(input);std::uint64_t after=0;
            if(!reader.u64(after)||!reader.done())return fail(reason,"Malformed state request.");
            return codec::encodeState(snapshot(after),output)||fail(reason,"Service state exceeds the response limit.");
        }
        if(operation==ReadProfile) {
            if(!input.empty())return fail(reason,"Malformed profile request.");
            return codec::encodeProfile(profile,output)||fail(reason,"Profile exceeds the response limit.");
        }
        if(operation==WriteProxy||operation==WriteTelegram) {
            Profile incoming;if(!codec::decodeProfile(input,incoming))return fail(reason,"Malformed profile update.");
            const bool telegram=operation==WriteTelegram;
            if(telegram?mt.running():proxy.running()){codec::erase(incoming);return fail(reason,u8"Перед изменением настроек остановите соответствующий компонент.");}
            Profile next=profile;
            if(telegram){next.mt=incoming.mt;next.mtAutoStart=incoming.mtAutoStart;next.tlsDomain=incoming.tlsDomain;}
            else{next.proxy=incoming.proxy;next.proxyAutoStart=incoming.proxyAutoStart;}
            codec::erase(incoming);
            bool ok=commitProfile(locations,profile,next,reason);
            if(ok) {
                Recovery& recovery=telegram?mtRecovery:proxyRecovery;recovery.desired=false;recovery.next=0;recovery.error.clear();
                codec::erase(profile);profile=std::move(next);error.clear();log("info",u8"Профиль службы сохранён с защитой этого компьютера.");
            }
            codec::erase(next);return ok;
        }
        if(!input.empty())return fail(reason,"Unexpected command payload.");
        switch(operation) {
            case ProxyOn:return start(false,false,reason);
            case TelegramOn:return start(true,false,reason);
            case ProxyOff:stop(false);return true;
            case TelegramOff:stop(true);return true;
            default:return fail(reason,"Unsupported service command.");
        }
    }
};

SERVICE_STATUS_HANDLE serviceStatusHandle=nullptr;
std::atomic<HANDLE> serviceStop{nullptr};
void reportStatus(DWORD state,DWORD code=NO_ERROR,DWORD checkpoint=0) {
    SERVICE_STATUS status={};status.dwServiceType=SERVICE_WIN32_OWN_PROCESS;status.dwCurrentState=state;
    status.dwControlsAccepted=state==SERVICE_RUNNING?SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN:0;
    status.dwWin32ExitCode=code;status.dwServiceSpecificExitCode=code==ERROR_SERVICE_SPECIFIC_ERROR?1:0;
    status.dwCheckPoint=checkpoint;status.dwWaitHint=(state==SERVICE_START_PENDING||state==SERVICE_STOP_PENDING)?15000:0;
    SetServiceStatus(serviceStatusHandle,&status);
}
DWORD WINAPI controlHandler(DWORD control,DWORD,void*,void*) {
    if(control==SERVICE_CONTROL_STOP||control==SERVICE_CONTROL_SHUTDOWN) {HANDLE stop=serviceStop.load();if(stop)SetEvent(stop);return NO_ERROR;}
    return control==SERVICE_CONTROL_INTERROGATE?NO_ERROR:ERROR_CALL_NOT_IMPLEMENTED;
}
bool serve(Runtime& runtime,HANDLE stop,std::string& error) {
    Descriptor descriptor;if(!descriptor.make(ObjectSddl))return fail(error,winError("Cannot create the local IPC ACL"));
    Handle pipe(CreateNamedPipeW(PipeName,PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,
                               PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,65536,65536,1000,&descriptor.attributes));
    if(!pipe.valid())return fail(error,winError("Cannot create the protected local service pipe"));
    reportStatus(SERVICE_RUNNING);
    runtime.log("info",u8"Служба запущена. Закрытие интерфейса и отключение RDP не останавливают прокси.");
    std::string reason;
    if(runtime.profile.proxyAutoStart)runtime.start(false,true,reason);
    if(runtime.profile.mtAutoStart)runtime.start(true,true,reason);
    while(WaitForSingleObject(stop,0)!=WAIT_OBJECT_0) {
        runtime.tick();auto connection=std::make_shared<PendingIo>(0);
        if(!connection->event.valid())return fail(error,winError("Cannot create the IPC connection event"));
        bool connected=ConnectNamedPipe(pipe.value,&connection->overlapped)!=FALSE;
        if(!connected) {
            DWORD code=GetLastError();
            if(code==ERROR_PIPE_CONNECTED)connected=true;
            else if(code==ERROR_IO_PENDING) {
                HANDLE events[]={stop,connection->event.value};
                for(;;) {
                    DWORD result=WaitForMultipleObjects(2,events,FALSE,250);
                    if(result==WAIT_OBJECT_0){cancelIo(pipe.value,connection);return true;}
                    if(result==WAIT_OBJECT_0+1){DWORD ignored=0;connected=GetOverlappedResult(pipe.value,&connection->overlapped,&ignored,FALSE)!=FALSE;break;}
                    if(result==WAIT_FAILED){cancelIo(pipe.value,connection);return fail(error,winError("Cannot wait for the local IPC connection"));}
                    runtime.tick();
                }
            } else return fail(error,winError("Cannot accept a local service connection",code));
        }
        if(connected) {
            std::uint32_t operation=0,size=0;Bytes input,output;std::string message;
            const ULONGLONG readDeadline=GetTickCount64()+IoTimeout;
            bool valid=readHeader(pipe.value,operation,size,readDeadline,stop,message)&&clientIsAdministrator(pipe.value);
            if(valid){input.resize(size);valid=transfer(pipe.value,input,false,readDeadline,stop,message);}
            if(valid) {
                bool ok=runtime.execute(operation,input,output,message);codec::erase(input);
                codec::Writer response;response.boolean(ok);response.text(runtime.safe(message));response.bytes(output);codec::erase(output);
                if(response.ok) {
                    const ULONGLONG replyDeadline=GetTickCount64()+IoTimeout;
                    if(sendFrame(pipe.value,operation|0x80000000u,response.data,replyDeadline,stop,message)) {
                        Bytes acknowledgment(1);
                        if(transfer(pipe.value,acknowledgment,false,replyDeadline,stop,message)&&acknowledgment[0]!=0xA5)
                            message="Invalid response acknowledgment.";
                    }
                }
                codec::erase(response.data);
            }
            codec::erase(input);codec::erase(output);
        }
        // No FlushFileBuffers: an uncooperative client must not block shutdown.
        DisconnectNamedPipe(pipe.value);
    }
    return true;
}
void WINAPI serviceMain(DWORD,LPWSTR*) {
    serviceStatusHandle=RegisterServiceCtrlHandlerExW(ServiceName,controlHandler,nullptr);
    if(!serviceStatusHandle)return;
    reportStatus(SERVICE_START_PENDING,NO_ERROR,1);
    Handle stop(CreateEventW(nullptr,TRUE,FALSE,nullptr));
    if(!stop.valid()){reportStatus(SERVICE_STOPPED,GetLastError());return;}
    serviceStop=stop.value;bool network=false,owned=false;DWORD exitCode=NO_ERROR;
    try {
        std::string error;State state;Paths locations;ScHandle scm,service;
        if(!lookup(state,locations,scm,service,0,error)||!state.installed||!same(executablePath(),locations.install+L"\\ProxyServer.exe"))throw static_cast<DWORD>(ERROR_ACCESS_DENIED);
        std::vector<Handle> installationLocks;
        if(!verifyInstallation(locations,installationLocks,error)||!directory(locations.data,false,installationLocks,error))throw static_cast<DWORD>(ERROR_ACCESS_DENIED);
        if(!acquireStandaloneOwnership(error))throw static_cast<DWORD>(ERROR_BUSY);
        owned=true;
        if(!proxy::networkInit(error))throw static_cast<DWORD>(ERROR_SERVICE_SPECIFIC_ERROR);
        network=true;reportStatus(SERVICE_START_PENDING,NO_ERROR,2);
        Runtime runtime(locations);
        if(!readProfileFile(locations,runtime.profile,error)||!validateProfile(runtime.profile,error)) {
            codec::erase(runtime.profile);runtime.profile=Profile();runtime.profile.manageFirewall=false;
            runtime.error=error;runtime.log("error",u8"Автозапуск отключён: профиль службы не прочитан. "+error);
        }
        if(!serve(runtime,stop.value,error)){runtime.error=error;exitCode=ERROR_SERVICE_SPECIFIC_ERROR;}
        reportStatus(SERVICE_STOP_PENDING,NO_ERROR,1);
        runtime.proxyRecovery.desired=false;runtime.mtRecovery.desired=false;runtime.proxy.stop();runtime.mt.stop();
    } catch(DWORD code){exitCode=code;reportStatus(SERVICE_STOP_PENDING,code,1);}
      catch(...){exitCode=ERROR_SERVICE_SPECIFIC_ERROR;reportStatus(SERVICE_STOP_PENDING,exitCode,1);}
    if(network)proxy::networkCleanup();
    if(owned)releaseStandaloneOwnership();
    serviceStop=nullptr;reportStatus(SERVICE_STOPPED,exitCode);
}
std::mutex ownershipGuard;
Handle engineOwnership;
bool replaceProfileBlob(const Paths& locations,const Bytes& blob,std::string& error) {
    std::wstring suffix;if(!randomName(suffix,error))return false;
    const std::wstring temporary=locations.data+L"\\rollback-"+suffix+L".tmp";
    if(!writeNew(temporary,blob,error))return false;
    if(MoveFileExW(nativePath(temporary).c_str(),nativePath(locations.data+L"\\profile.dpapi").c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))return true;
    DWORD code=GetLastError();DeleteFileW(nativePath(temporary).c_str());return fail(error,winError("Cannot restore the previous protected profile",code));
}
}

bool isElevated() {
    Handle token;HANDLE raw=nullptr;if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&raw))return false;token.reset(raw);
    TOKEN_ELEVATION elevation={};DWORD size=0;if(!GetTokenInformation(token.value,TokenElevation,&elevation,sizeof(elevation),&size)||!elevation.TokenIsElevated)return false;
    BYTE sid[SECURITY_MAX_SID_SIZE]={};size=sizeof(sid);BOOL member=FALSE;
    return CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,sid,&size)&&CheckTokenMembership(nullptr,sid,&member)&&member;
}
bool acquireStandaloneOwnership(std::string& error) {
    std::lock_guard<std::mutex> guard(ownershipGuard);if(engineOwnership.valid())return true;
    Descriptor descriptor;if(!descriptor.make(ObjectSddl))return fail(error,winError("Cannot create the engine ownership ACL"));
    Handle handle(CreateMutexW(&descriptor.attributes,FALSE,EngineMutexName));
    if(!handle.valid())return fail(error,winError("Cannot acquire proxy engine ownership"));
    if(GetLastError()==ERROR_ALREADY_EXISTS)return fail(error,u8"Движки уже принадлежат другому экземпляру программы или службе. Сначала остановите их там.");
    engineOwnership=std::move(handle);error.clear();return true;
}
void releaseStandaloneOwnership(){std::lock_guard<std::mutex> guard(ownershipGuard);engineOwnership.reset();}
bool dispatchIfService(const wchar_t*,int& exitCode) {
    int count=0;LPWSTR* args=CommandLineToArgvW(GetCommandLineW(),&count);if(!args)return false;
    bool service=false;for(int i=1;i<count;++i)if(wcscmp(args[i],L"--service")==0)service=true;
    const bool valid=count==2;LocalFree(args);if(!service)return false;
    if(!valid){exitCode=ERROR_INVALID_PARAMETER;return true;}
    SERVICE_TABLE_ENTRYW table[]={{const_cast<LPWSTR>(ServiceName),serviceMain},{nullptr,nullptr}};
    exitCode=StartServiceCtrlDispatcherW(table)?0:static_cast<int>(GetLastError());return true;
}
bool getState(State& state,std::string& error,std::uint64_t afterEvent) {
    state=State();error.clear();Paths locations;ScHandle scm,service;
    if(!lookup(state,locations,scm,service,0,error)){state.error=error;return false;}
    if(!state.installed||state.scmState!=SERVICE_RUNNING)return true;
    codec::Writer input;input.u64(afterEvent);Bytes output;
    if(!request(Query,input.data,output,error)){state.error=error;return false;}
    State remote;if(!codec::decodeState(output,remote))return fail(error,"Malformed state response from the service.");
    remote.installDir=state.installDir;remote.dataDir=state.dataDir;remote.installed=true;remote.scmState=state.scmState;state=std::move(remote);return true;
}
bool loadProfile(Profile& profile,std::string& error) {
    State state;Paths locations;ScHandle scm,service;
    if(!isElevated())return fail(error,u8"Для чтения профиля службы нужны права администратора.");
    if(!lookup(state,locations,scm,service,0,error))return false;
    if(!state.installed)return fail(error,u8"Служба не установлена.");
    if(state.scmState==SERVICE_STOPPED)return readProfileFile(locations,profile,error);
    Bytes output;if(!request(ReadProfile,Bytes(),output,error))return false;
    bool ok=codec::decodeProfile(output,profile);codec::erase(output);return ok||fail(error,"Malformed service profile response.");
}
bool install(const Profile& supplied,std::string& error) {
    error.clear();if(!isElevated())return fail(error,u8"Для установки службы нужны права администратора.");
    ManagementLock operation;if(!operation.acquire(error))return false;
    State state;Paths locations;ScHandle queryScm,existing;
    if(!lookup(state,locations,queryScm,existing,0,error))return false;
    if(state.installed)return fail(error,u8"Служба уже установлена. Для нового выпуска сначала остановите и удалите службу; её профиль сохранится.");
    Profile profile=supplied;
    struct ProfileCleanup {Profile& p;~ProfileCleanup(){codec::erase(p);}} cleanProfile{profile};
    if(!validateProfile(profile,error))return false;
    std::wstring source;if(!canonical(executablePath(),source,error))return false;
    const std::wstring sourceDirectory=source.substr(0,source.find_last_of(L'\\'));
    std::wstring suffix;if(!randomName(suffix,error))return false;
    locations.install=locations.root+L"\\host-"+suffix;
    std::vector<Handle> locks;
    if(!directory(locations.root,true,locks,error)||!directory(locations.data,true,locks,error)||
       !directory(locations.install,true,locks,error)||!directory(locations.install+L"\\components",true,locks,error))return false;
    const std::wstring profilePath=locations.data+L"\\profile.dpapi";
    const bool previousExists=GetFileAttributesW(nativePath(profilePath).c_str())!=INVALID_FILE_ATTRIBUTES;
    Bytes previous;
    if(previousExists&&!readFile(profilePath,previous,codec::MaxPayload+16384,true,error))return false;
    bool profileWritten=false,firewallApplied=false,serviceCreated=false,keepFiles=false;
    ScHandle manager,created;
    auto rollback=[&]()->bool {
        if(serviceCreated&&!DeleteService(created.value)) {
            const DWORD code=GetLastError();
            if(code!=ERROR_SERVICE_MARKED_FOR_DELETE) {
                keepFiles=true;error+=u8" Служба создана, но остаётся остановленной: откат записи SCM не выполнен (код "+std::to_string(code)+u8"). Файлы и профиль сохранены; проверьте состояние службы.";
                return false;
            }
        }
        if(firewallApplied) {
            std::string problem;if(!service_firewall::remove(locations.install,problem))error+=u8" Откат правил брандмауэра не завершён: "+problem;
        }
        if(profileWritten) {
            std::string problem;
            if(previousExists) {if(!replaceProfileBlob(locations,previous,problem))error+=u8" Не восстановлен прежний профиль: "+problem;}
            else if(!DeleteFileW(nativePath(profilePath).c_str()))error+=u8" Не удалось удалить новый профиль при откате.";
        }
        return false;
    };
    bool success=false;
    do {
        const wchar_t* targets[]={L"\\ProxyServer.exe",L"\\components\\gost.exe",L"\\components\\mtg.exe",L"\\components\\proxy-cert.exe"};
        for(unsigned i=0;i<4;++i) {
            const std::wstring origin=i?sourceDirectory+targets[i]:source;
            Bytes bytes;
            if(!readFile(origin,bytes,128*1024*1024,false,error)||!writeNew(locations.install+targets[i],bytes,error))break;
            if(i==3)success=true;
        }
        if(!success)break;
        success=false;
        if(!importTls(locations,profile,error)||!writeProfileFile(locations,profile,error))break;
        profileWritten=true;
        if(!applyFirewall(locations,profile,error))break;
        firewallApplied=profile.manageFirewall;
        manager.value=OpenSCManagerW(nullptr,nullptr,SC_MANAGER_CREATE_SERVICE);
        if(!manager.value){error=winError("Cannot open the service manager for installation");break;}
        const std::wstring binary=L"\""+locations.install+L"\\ProxyServer.exe\" --service";
        created.value=CreateServiceW(manager.value,ServiceName,L"Proxy Server 2.1",SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,SERVICE_AUTO_START,SERVICE_ERROR_NORMAL,binary.c_str(),nullptr,nullptr,L"Tcpip\0",nullptr,nullptr);
        if(!created.value){error=winError("Cannot register the Windows proxy service");break;}
        serviceCreated=true;
        Descriptor descriptor;if(!descriptor.make(ObjectSddl)||!SetServiceObjectSecurity(created.value,DACL_SECURITY_INFORMATION,descriptor.value))
            {error=winError("Cannot protect the service control permissions");break;}
        SERVICE_DESCRIPTIONW description={const_cast<LPWSTR>(L"Runs the configured GOST and MTProto engines without an interactive login. Managed by Proxy Server 2.1.")};
        SC_ACTION actions[]={{SC_ACTION_RESTART,5000},{SC_ACTION_RESTART,15000},{SC_ACTION_RESTART,60000},{SC_ACTION_NONE,0}};
        SERVICE_FAILURE_ACTIONSW recovery={};recovery.dwResetPeriod=86400;recovery.cActions=4;recovery.lpsaActions=actions;
        if(!ChangeServiceConfig2W(created.value,SERVICE_CONFIG_DESCRIPTION,&description)||
           !ChangeServiceConfig2W(created.value,SERVICE_CONFIG_FAILURE_ACTIONS,&recovery))
            {error=winError("Cannot configure service description and bounded crash recovery");break;}
        success=true;
    } while(false);
    if(!success)rollback();
    locks.clear();
    if(!success&&!keepFiles) {
        const wchar_t* files[]={L"\\ProxyServer.exe",L"\\components\\gost.exe",L"\\components\\mtg.exe",L"\\components\\proxy-cert.exe"};
        for(const wchar_t* file:files)DeleteFileW(nativePath(locations.install+file).c_str());
        RemoveDirectoryW(nativePath(locations.install+L"\\components").c_str());RemoveDirectoryW(nativePath(locations.install).c_str());
    }
    if(success)error.clear();
    return success;
}
bool startService(std::string& error) {
    error.clear();if(!isElevated())return fail(error,u8"Для запуска службы нужны права администратора.");
    ManagementLock operation;if(!operation.acquire(error))return false;
    State state;Paths locations;ScHandle scm,service;
    if(!lookup(state,locations,scm,service,SERVICE_START,error))return false;
    if(!state.installed)return fail(error,u8"Служба не установлена.");
    if(state.scmState==SERVICE_RUNNING)return true;
    if(state.scmState==SERVICE_START_PENDING)return waitService(service.value,SERVICE_RUNNING,error);
    if(state.scmState!=SERVICE_STOPPED)return fail(error,u8"Служба ещё меняет состояние. Дождитесь завершения операции.");
    std::vector<Handle> locks;if(!verifyInstallation(locations,locks,error))return false;
    if(!StartServiceW(service.value,0,nullptr)&&GetLastError()!=ERROR_SERVICE_ALREADY_RUNNING)return fail(error,winError("Cannot start the Windows proxy service"));
    return waitService(service.value,SERVICE_RUNNING,error);
}
bool stopService(std::string& error) {
    error.clear();if(!isElevated())return fail(error,u8"Для остановки службы нужны права администратора.");
    ManagementLock operation;if(!operation.acquire(error))return false;
    State state;Paths locations;ScHandle scm,service;
    if(!lookup(state,locations,scm,service,SERVICE_STOP,error))return false;
    if(!state.installed||state.scmState==SERVICE_STOPPED)return true;
    if(state.scmState!=SERVICE_STOP_PENDING) {
        SERVICE_STATUS status={};if(!ControlService(service.value,SERVICE_CONTROL_STOP,&status)&&GetLastError()!=ERROR_SERVICE_NOT_ACTIVE)
            return fail(error,winError("Cannot request service shutdown"));
    }
    return waitService(service.value,SERVICE_STOPPED,error);
}
bool uninstall(std::string& error) {
    error.clear();if(!isElevated())return fail(error,u8"Для удаления службы нужны права администратора.");
    ManagementLock operation;if(!operation.acquire(error))return false;
    State state;Paths locations;ScHandle scm,service;
    if(!lookup(state,locations,scm,service,SERVICE_STOP|DELETE,error))return false;
    if(!state.installed)return true;
    if(state.scmState!=SERVICE_STOPPED) {
        if(state.scmState!=SERVICE_STOP_PENDING){SERVICE_STATUS status={};if(!ControlService(service.value,SERVICE_CONTROL_STOP,&status)&&GetLastError()!=ERROR_SERVICE_NOT_ACTIVE)return fail(error,winError("Cannot stop the service before removal"));}
        if(!waitService(service.value,SERVICE_STOPPED,error))return false;
    }
    Profile removalProfile;std::string profileError;
    const bool profileReadable=readProfileFile(locations,removalProfile,profileError);
    const bool removeFirewall=!profileReadable||removalProfile.manageFirewall;
    codec::erase(removalProfile);
    if(removeFirewall&&!service_firewall::remove(locations.install,error))return false;
    if(!DeleteService(service.value)&&GetLastError()!=ERROR_SERVICE_MARKED_FOR_DELETE) {
        error=winError("Cannot remove the service registration");Profile profile;std::string rollback;
        if(readProfileFile(locations,profile,rollback)&&profile.manageFirewall&&!applyFirewall(locations,profile,rollback))error+=u8" Не восстановлены правила брандмауэра: "+rollback;
        codec::erase(profile);return false;
    }
    // Keep protected profiles, imported TLS material and binaries. In particular
    // never delete the executable that may currently display this management UI.
    return true;
}
namespace {
bool savePart(Profile& incoming,bool telegram,std::string& error) {
    if(!isElevated())return fail(error,u8"Для изменения профиля службы нужны права администратора.");
    ManagementLock operation;if(!operation.acquire(error))return false;
    State state;Paths locations;ScHandle scm,service;
    if(!lookup(state,locations,scm,service,0,error))return false;
    if(!state.installed)return fail(error,u8"Служба не установлена.");
    if(state.scmState==SERVICE_STOPPED) {
        Profile previous;if(!readProfileFile(locations,previous,error))return false;
        Profile next=previous;
        if(telegram){next.mt=incoming.mt;next.mtAutoStart=incoming.mtAutoStart;next.tlsDomain=incoming.tlsDomain;}
        else{next.proxy=incoming.proxy;next.proxyAutoStart=incoming.proxyAutoStart;}
        bool ok=commitProfile(locations,previous,next,error);codec::erase(previous);codec::erase(next);return ok;
    }
    Bytes input,output;if(!codec::encodeProfile(incoming,input))return fail(error,"Profile update exceeds the local IPC limit.");
    const bool ok=request(telegram?WriteTelegram:WriteProxy,input,output,error);codec::erase(input);codec::erase(output);return ok;
}
}
bool saveProxy(const proxy::Config& config,bool autoStart,std::string& error) {
    Profile incoming;incoming.proxy=config;incoming.proxyAutoStart=autoStart;const bool ok=savePart(incoming,false,error);codec::erase(incoming);return ok;
}
bool saveTelegram(const mtproto::Config& config,bool autoStart,const std::string& tlsDomain,std::string& error) {
    Profile incoming;incoming.mt=config;incoming.mtAutoStart=autoStart;incoming.tlsDomain=tlsDomain;const bool ok=savePart(incoming,true,error);codec::erase(incoming);return ok;
}
bool command(Command value,std::string& error) {
    std::uint32_t operation=0;
    switch(value){case Command::StartProxy:operation=ProxyOn;break;case Command::StopProxy:operation=ProxyOff;break;case Command::StartTelegram:operation=TelegramOn;break;case Command::StopTelegram:operation=TelegramOff;break;default:return fail(error,"Unknown service command.");}
    Bytes output;return request(operation,Bytes(),output,error);
}
}
