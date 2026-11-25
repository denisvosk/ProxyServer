#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <netfw.h>
#include <algorithm>
#include <memory>
#include <set>
#include <sstream>
#include "service_firewall.h"

namespace service_firewall {
namespace {
template<class T> struct Release { void operator()(T* p) const { if(p)p->Release(); } };
template<class T> using Com = std::unique_ptr<T,Release<T> >;
struct Bstr {
    BSTR value;
    explicit Bstr(const std::wstring& s):value(SysAllocStringLen(s.data(),static_cast<UINT>(s.size()))){}
    ~Bstr(){SysFreeString(value);}
    Bstr(const Bstr&)=delete;Bstr& operator=(const Bstr&)=delete;
};
struct Apartment {
    HRESULT hr;
    Apartment():hr(CoInitializeEx(nullptr,COINIT_MULTITHREADED)){}
    ~Apartment(){if(SUCCEEDED(hr))CoUninitialize();}
    bool valid()const{return SUCCEEDED(hr)||hr==RPC_E_CHANGED_MODE;}
};
bool fail(std::string& e,const char* operation,HRESULT hr) {
    std::ostringstream s;s<<"FIREWALL_"<<operation<<" (0x"<<std::hex<<static_cast<unsigned long>(hr)<<")";e=s.str();return false;
}
bool samePath(const std::wstring& a,const std::wstring& b){return _wcsicmp(a.c_str(),b.c_str())==0;}
std::wstring enginePath(std::wstring root,const wchar_t* file) {
    std::replace(root.begin(),root.end(),L'/',L'\\');while(!root.empty()&&root.back()==L'\\')root.pop_back();
    return root+L"\\components\\"+file;
}
typedef HRESULT (STDMETHODCALLTYPE INetFwRule::*TextGetter)(BSTR*);
bool getText(INetFwRule* r,TextGetter get,std::wstring& out) {
    BSTR b=nullptr;HRESULT hr=(r->*get)(&b);
    if(SUCCEEDED(hr))out.assign(b?b:L"",b?SysStringLen(b):0);
    SysFreeString(b);return SUCCEEDED(hr);
}
bool validOwnedName(const std::wstring& name,const std::wstring& prefix) {
    if(name.compare(0,prefix.size(),prefix)!=0)return false;
    const std::wstring tail=name.substr(prefix.size());std::size_t dot=tail.find(L'.');
    if(dot==std::wstring::npos)return false;
    const std::wstring kind=tail.substr(0,dot),digest=tail.substr(dot+1);
    if(kind!=L"gost-tcp"&&kind!=L"gost-udp"&&kind!=L"mtg-tcp")return false;
    if(digest.size()!=16)return false;
    for(wchar_t c:digest)if(!((c>=L'0'&&c<=L'9')||(c>=L'a'&&c<=L'f')))return false;
    return true;
}
bool owns(INetFwRule* r,const std::wstring& directory,std::wstring& name) {
    std::wstring group,marker,app;
    if(!getText(r,&INetFwRule::get_Name,name)||!validOwnedName(name,installationPrefix(directory))||
       !getText(r,&INetFwRule::get_Grouping,group)||group!=groupName()||
       !getText(r,&INetFwRule::get_Description,marker)||marker!=description()||
       !getText(r,&INetFwRule::get_ApplicationName,app))return false;
    const bool mt=name.find(L".mtg-tcp.")!=std::wstring::npos;
    if(!samePath(app,enginePath(directory,mt?L"mtg.exe":L"gost.exe")))return false;
    NET_FW_RULE_DIRECTION direction;NET_FW_ACTION action;long protocol=0;
    return SUCCEEDED(r->get_Direction(&direction))&&direction==NET_FW_RULE_DIR_IN&&
           SUCCEEDED(r->get_Action(&action))&&action==NET_FW_ACTION_ALLOW&&
           SUCCEEDED(r->get_Protocol(&protocol))&&protocol==(name.find(L".gost-udp.")!=std::wstring::npos?17:6);
}
struct Existing {std::wstring name;std::shared_ptr<INetFwRule> rule;};
bool ownedRules(INetFwRules* rules,const std::wstring& directory,std::vector<Existing>& out,std::string& error) {
    IUnknown* unknown=nullptr;HRESULT hr=rules->get__NewEnum(&unknown);if(FAILED(hr))return fail(error,"ENUM",hr);
    Com<IUnknown> ownedUnknown(unknown);IEnumVARIANT* enumerator=nullptr;
    hr=unknown->QueryInterface(IID_IEnumVARIANT,reinterpret_cast<void**>(&enumerator));if(FAILED(hr))return fail(error,"ENUM_INTERFACE",hr);
    Com<IEnumVARIANT> ownedEnum(enumerator);
    for(unsigned count=0;count<65536;++count) {
        VARIANT value;VariantInit(&value);ULONG fetched=0;hr=enumerator->Next(1,&value,&fetched);
        if(FAILED(hr)){VariantClear(&value);return fail(error,"ENUM_NEXT",hr);}
        if(hr==S_FALSE||!fetched){VariantClear(&value);return true;}
        INetFwRule* rule=nullptr;
        if(value.vt==VT_DISPATCH&&value.pdispVal)hr=value.pdispVal->QueryInterface(__uuidof(INetFwRule),reinterpret_cast<void**>(&rule));
        else if(value.vt==VT_UNKNOWN&&value.punkVal)hr=value.punkVal->QueryInterface(__uuidof(INetFwRule),reinterpret_cast<void**>(&rule));
        else hr=E_NOINTERFACE;
        VariantClear(&value);
        if(SUCCEEDED(hr)&&rule){
            std::shared_ptr<INetFwRule> keep(rule,Release<INetFwRule>());Existing item;
            if(owns(rule,directory,item.name)){item.rule=keep;out.push_back(item);}
        }
    }
    return fail(error,"RULE_LIMIT",E_FAIL);
}
bool equalPlan(INetFwRule* rule,const Rule& plan) {
    std::wstring app,ports,local,remote;long protocol=0,profiles=0;VARIANT_BOOL enabled=VARIANT_FALSE,edge=VARIANT_TRUE;
    return getText(rule,&INetFwRule::get_ApplicationName,app)&&samePath(app,plan.application)&&
        getText(rule,&INetFwRule::get_LocalPorts,ports)&&ports==plan.localPorts&&
        getText(rule,&INetFwRule::get_LocalAddresses,local)&&equivalentAddressScope(local,plan.localAddresses)&&
        getText(rule,&INetFwRule::get_RemoteAddresses,remote)&&equivalentAddressScope(remote,plan.remoteAddresses)&&
        SUCCEEDED(rule->get_Protocol(&protocol))&&protocol==plan.protocol&&
        SUCCEEDED(rule->get_Profiles(&profiles))&&profiles==NET_FW_PROFILE2_ALL&&
        SUCCEEDED(rule->get_Enabled(&enabled))&&enabled==VARIANT_TRUE&&
        SUCCEEDED(rule->get_EdgeTraversal(&edge))&&edge==VARIANT_FALSE;
}
bool createRule(const Rule& r,Com<INetFwRule>& result,std::string& error) {
    INetFwRule* raw=nullptr;HRESULT hr=CoCreateInstance(__uuidof(NetFwRule),nullptr,CLSCTX_INPROC_SERVER,
                                                     __uuidof(INetFwRule),reinterpret_cast<void**>(&raw));
    if(FAILED(hr))return fail(error,"CREATE",hr);
    result.reset(raw);
    Bstr name(r.name),app(r.application),ports(r.localPorts),local(r.localAddresses),remote(r.remoteAddresses),
         group(groupName()),marker(description()),interfaces(L"All");
    if(!name.value||!app.value||!ports.value||!local.value||!remote.value||!group.value||!marker.value||!interfaces.value)
        return fail(error,"ALLOCATE",E_OUTOFMEMORY);
    // Protocol precedes LocalPorts, as required by INetFwRule.
    if(FAILED(hr=raw->put_Name(name.value))||FAILED(hr=raw->put_Description(marker.value))||
       FAILED(hr=raw->put_Grouping(group.value))||FAILED(hr=raw->put_ApplicationName(app.value))||
       FAILED(hr=raw->put_Protocol(r.protocol))||FAILED(hr=raw->put_LocalPorts(ports.value))||
       FAILED(hr=raw->put_LocalAddresses(local.value))||FAILED(hr=raw->put_RemoteAddresses(remote.value))||
       FAILED(hr=raw->put_Direction(NET_FW_RULE_DIR_IN))||FAILED(hr=raw->put_Action(NET_FW_ACTION_ALLOW))||
       FAILED(hr=raw->put_Profiles(NET_FW_PROFILE2_ALL))||FAILED(hr=raw->put_InterfaceTypes(interfaces.value))||
       FAILED(hr=raw->put_EdgeTraversal(VARIANT_FALSE))||FAILED(hr=raw->put_Enabled(VARIANT_TRUE)))return fail(error,"SET_RULE",hr);
    return true;
}
bool openRules(Com<INetFwPolicy2>& policy,Com<INetFwRules>& rules,std::string& error) {
    INetFwPolicy2* raw=nullptr;HRESULT hr=CoCreateInstance(__uuidof(NetFwPolicy2),nullptr,CLSCTX_INPROC_SERVER,
                                                       __uuidof(INetFwPolicy2),reinterpret_cast<void**>(&raw));
    if(FAILED(hr))return fail(error,"OPEN",hr);
    policy.reset(raw);INetFwRules* r=nullptr;
    hr=raw->get_Rules(&r);if(FAILED(hr))return fail(error,"GET_RULES",hr);rules.reset(r);return true;
}
void rollback(INetFwRules* rules,const std::vector<Existing>& removed,const std::vector<std::wstring>& added,std::string& error) {
    bool failed=false;
    for(const Existing& r:removed)if(FAILED(rules->Add(r.rule.get())))failed=true;
    for(const std::wstring& name:added){Bstr b(name);if(!b.value||FAILED(rules->Remove(b.value)))failed=true;}
    if(failed)error+="; FIREWALL_ROLLBACK_FAILED: check only the Proxy Server 2.1 managed group";
}
}
bool apply(const proxy::Config& p,const mtproto::Config& mt,const std::wstring& directory,bool includeMTProto,std::string& error) {
    std::vector<Rule> plan;if(!makePlan(p,mt,directory,includeMTProto,plan,error))return false;
    Apartment apartment;if(!apartment.valid())return fail(error,"COM",apartment.hr);
    Com<INetFwPolicy2> policy;Com<INetFwRules> rules;if(!openRules(policy,rules,error))return false;
    std::vector<Existing> before;if(!ownedRules(rules.get(),directory,before,error))return false;
    std::vector<std::wstring> added;std::vector<Existing> removed;std::set<std::wstring> desired;
    for(const Rule& r:plan) {
        desired.insert(r.name);Bstr name(r.name);INetFwRule* existing=nullptr;
        if(!name.value){fail(error,"ALLOCATE",E_OUTOFMEMORY);rollback(rules.get(),removed,added,error);return false;}
        const HRESULT found=rules->Item(name.value,&existing);Com<INetFwRule> keep(existing);
        if(SUCCEEDED(found)) {
            std::wstring actualName;
            if(!existing||!owns(existing,directory,actualName)||!equalPlan(existing,r)){
                error="FIREWALL_RULE_NAME_CONFLICT";rollback(rules.get(),removed,added,error);return false;
            }
            continue;
        }
        if(found!=HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)&&found!=HRESULT_FROM_WIN32(ERROR_NOT_FOUND)){
            fail(error,"FIND_RULE",found);rollback(rules.get(),removed,added,error);return false;
        }
        Com<INetFwRule> fresh;if(!createRule(r,fresh,error)){rollback(rules.get(),removed,added,error);return false;}
        HRESULT hr=rules->Add(fresh.get());if(FAILED(hr)){fail(error,"ADD",hr);rollback(rules.get(),removed,added,error);return false;}
        added.push_back(r.name);
    }
    for(const Existing& old:before)if(!desired.count(old.name)) {
        Bstr name(old.name);HRESULT hr=name.value?rules->Remove(name.value):E_OUTOFMEMORY;
        if(FAILED(hr)){fail(error,"REMOVE_SUPERSEDED",hr);rollback(rules.get(),removed,added,error);return false;}
        removed.push_back(old);
    }
    return true;
}
bool remove(const std::wstring& directory,std::string& error) {
    error.clear();Apartment apartment;if(!apartment.valid())return fail(error,"COM",apartment.hr);
    Com<INetFwPolicy2> policy;Com<INetFwRules> rules;if(!openRules(policy,rules,error))return false;
    std::vector<Existing> before;if(!ownedRules(rules.get(),directory,before,error))return false;
    std::vector<Existing> removed;const std::vector<std::wstring> added;
    for(const Existing& old:before) {
        Bstr name(old.name);HRESULT hr=name.value?rules->Remove(name.value):E_OUTOFMEMORY;
        if(FAILED(hr)){fail(error,"REMOVE",hr);rollback(rules.get(),removed,added,error);return false;}
        removed.push_back(old);
    }
    return true;
}
}
