// Proxy Server 2.1 — native Unicode Win32 desktop application.
// Service setup may add its own narrowly scoped firewall rules after explicit selection.
// RDP, network profiles and system-wide proxy settings are never changed.
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
#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>
#include <commdlg.h>
#include <wincrypt.h>
#include <algorithm>
#include <atomic>
#include <memory>
#include <thread>
#include <utility>
#include <cmath>
#include <cstdint>
#include <cwchar>
#include <deque>
#include <string>
#include <vector>
#include "proxy_core.h"
#include "mtproto_win.h"
#include "service_host.h"
#ifdef _MSC_VER
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"crypt32.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"comctl32.lib")
#pragma comment(lib,"comdlg32.lib")
#pragma comment(lib,"user32.lib")
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"gdi32.lib")
#endif

namespace {
const wchar_t* const AppName=L"Proxy Server";
const wchar_t* const AppClass=L"PrivateNativeProxyWindowV2";
const wchar_t* const ContentClass=L"PrivateNativeProxyContentV2";
const wchar_t* const RunValue=L"PrivateProxyServer";
const UINT TrayMessage=WM_APP+7;
const UINT RevealMessage=WM_APP+8;
const UINT ServiceCompleteMessage=WM_APP+9;
const int Sidebar=202, Margin=28;
enum Page { Overview, Settings, Chain, TlsDns, Telegram, Service, Journal };
enum Id {
    NavOverview=100,NavSettings,NavChain,NavTlsDns,NavTelegram,NavService,NavJournal,Help,Exit,Toggle,Save,SaveStart,
    User,Password,ShowPassword,GeneratePassword,EnableSocks,EnableHttp,SocksPort,HttpPort,
    BindAddress,AllowIp,AutoProxy,AutoWindows,CloseTray,MaxConnections,ConnectTimeout,IdleTimeout,
    EnableChainSocks,EnableChainHttp,ChainSocksPort,ChainHttpPort,UpstreamType,UpstreamHost,UpstreamPort,UpstreamUser,UpstreamPassword,ShowUpstreamPassword,
    EnableHttps,HttpsPort,EnableSocksTls,SocksTlsPort,TlsCert,TlsKey,BrowseTlsCert,BrowseTlsKey,TlsCertHost,GenerateTlsCert,TlsUseChain,DnsServer,EnableDns,DnsPort,SocksUdp,UdpPortMin,UdpPortMax,
    MtBind,MtPort,MtPublicHost,MtDomain,MtSecret,MtShowSecret,MtGenerate,MtAuto,MtSave,MtToggle,MtCopyLink,
    ServiceInstall,ServiceStart,ServiceStop,ServiceRemove,ServiceRefresh,ServiceOpenData,ServiceProxyAuto,ServiceMtAuto,ServiceFirewall,
    ExportLog,CopyLog,OpenFolder,TrayOpen=1000,TrayStart,TrayStop,TrayMtStart,TrayMtStop,TrayExit
};
struct Control { HWND hwnd; int id; Page page; bool common; };
struct Fonts { HFONT normal=nullptr,small=nullptr,medium=nullptr,title=nullptr,number=nullptr,brand=nullptr; } fonts;
struct JournalRow { std::wstring time,level,message; };
HINSTANCE instance=nullptr;
HWND window=nullptr,content=nullptr,logList=nullptr;
std::vector<Control> controls;
HWND nav[7]={}; HWND helpButton=nullptr,exitButton=nullptr,toggleButton=nullptr;
HBRUSH editBrush=nullptr,whiteBrush=nullptr,bgBrush=nullptr;
HICON appIcon=nullptr;
int dpi=96,scrollY=0,scrollX=0,contentWidth=780,contentHeight=720,viewportWidth=780;
Page currentPage=Overview,fieldErrorPage=Settings;
bool loading=false,dirty=false,closeToTray=true,trayPresent=false,firstHide=true,quitting=false,lastRunning=false,logWriteFailed=false;
NOTIFYICONDATAW tray={};
UINT taskbarCreated=0;
std::wstring iniPath,exePath,appDir,logPath,banner;
bool bannerError=false;
proxy::Server server;
mtproto::Controller mtController;
child_process::Process certProcess;
std::wstring certOutputDir;
bool certGenerating=false;
mtproto::Config mtConfigured;
std::wstring mtDomain=L"www.microsoft.com",mtBanner;
bool mtAutostart=false,mtDirty=false,mtBannerError=false,mtLastRunning=false;
proxy::Config configured;
proxy::Stats latest,previous;
ULONGLONG lastSample=0,sessionStarted=0;
double uploadMbps=0,downloadMbps=0;
std::deque<double> uploadHistory,downloadHistory;
std::deque<JournalRow> journalRows;
std::uint64_t lastCoreEvent=0;

enum class ServiceAction { Discover, Poll, Reload, Install, ActivateInstalled, Start, Stop, Remove,
                           SaveProxy, SaveProxyStart, SaveTelegram, SaveTelegramStart, StopProxy, StopTelegram };
struct ServiceRequest {
    ServiceAction action=ServiceAction::Poll;
    service_host::Profile profile;
    bool restoreProxy=false,restoreMt=false;
    std::uint64_t afterEvent=0;
};
struct ServiceReply {
    ServiceRequest request;
    service_host::State state;
    service_host::Profile profile;
    bool ok=false,stateOk=false,profileLoaded=false;
    std::string error,stateError;
};
service_host::State serviceState;
std::thread serviceWorker;
std::atomic<bool> serviceFinished(false);
std::unique_ptr<ServiceRequest> queuedServiceRequest;
ServiceReply serviceReply;
ServiceAction activeServiceAction=ServiceAction::Discover;
bool serviceWorkerActive=false,serviceChecked=false,serviceStatusKnown=false,serviceInstalled=false,serviceProfileLoaded=false;
bool serviceInitialDiscovery=true,standaloneAutoProxy=false,standaloneAutoMt=false,serviceOptionsDirty=false;
bool serviceFirewall=true;
std::uint64_t lastServiceEvent=0;
ULONGLONG lastServicePoll=0;
std::wstring serviceBanner,legacyStartupWarning;
bool serviceBannerError=false;
bool serviceMode() { return serviceInstalled; }
bool serviceMutationBusy() {
    return queuedServiceRequest.get()!=nullptr||(serviceWorkerActive&&activeServiceAction!=ServiceAction::Poll);
}
bool proxyRunning() { return serviceMode()?serviceState.reachable&&serviceState.proxyRunning:server.running(); }
bool telegramRunning() { return serviceMode()?serviceState.reachable&&serviceState.mtRunning:mtController.running(); }
bool engineStateUnknown() { return !serviceChecked||!serviceStatusKnown||(serviceMode()&&serviceState.scmState!=SERVICE_STOPPED&&!serviceState.reachable); }
bool canUseBackend() { return serviceChecked&&serviceStatusKnown&&!serviceMutationBusy()&&(!serviceMode()||(serviceProfileLoaded&&(serviceState.reachable||serviceState.scmState==SERVICE_STOPPED))); }
void queueServiceRequest(ServiceRequest request);
void consumeServiceReply();
void refreshServiceControls();
bool protectedApplicationFolder();
void refreshServiceDefaults();
void updateState();
void updateMtState();
void sample();
void startServer(bool fromLoaded=false);
void startMt(bool fromLoaded=false);
void clearProfile(service_host::Profile& profile) {
    if(!profile.proxy.password.empty())SecureZeroMemory(&profile.proxy.password[0],profile.proxy.password.size());
    profile.proxy.password.clear();
    if(!profile.proxy.upstreamPassword.empty())SecureZeroMemory(&profile.proxy.upstreamPassword[0],profile.proxy.upstreamPassword.size());
    profile.proxy.upstreamPassword.clear();
    if(!profile.mt.secret.empty())SecureZeroMemory(&profile.mt.secret[0],profile.mt.secret.size());
    profile.mt.secret.clear();
}

const COLORREF Canvas=RGB(244,247,251),White=RGB(255,255,255),Text=RGB(25,38,59),Muted=RGB(102,117,137),Border=RGB(225,231,239);
const COLORREF Blue=RGB(34,105,222),Green=RGB(16,155,119),Dark=RGB(22,34,55),DarkHover=RGB(39,55,81),Red=RGB(188,55,63);
template<std::size_t N> void copyBuffer(wchar_t (&destination)[N],const wchar_t* source) {
    const std::size_t count=(std::min)(N-1,wcslen(source));std::copy(source,source+count,destination);destination[count]=L'\0';
}
int px(int n) { return MulDiv(n,dpi,96); }
int dip(int n) { return MulDiv(n,96,dpi); }
HWND control(int id) { for(const auto& c:controls) if(c.id==id)return c.hwnd; return nullptr; }
std::wstring getText(HWND h) { int n=GetWindowTextLengthW(h); std::vector<wchar_t> b(static_cast<std::size_t>(n)+1); GetWindowTextW(h,b.data(),n+1); return b.data(); }
void setText(int id,const std::wstring& s) { SetWindowTextW(control(id),s.c_str()); }
bool checked(int id) { return SendMessageW(control(id),BM_GETCHECK,0,0)==BST_CHECKED; }
void check(int id,bool b) { SendMessageW(control(id),BM_SETCHECK,b?BST_CHECKED:BST_UNCHECKED,0); }
std::string ascii(const std::wstring& s) { std::string r; for(wchar_t c:s) { if(c>127)return std::string(1,'\x01'); r.push_back(static_cast<char>(c)); } return r; }
std::wstring wide(const std::string& s) {
    if(s.empty())return L"";
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);
    if(!n)return std::wstring(s.begin(),s.end());
    std::wstring w(n,L'\0'); MultiByteToWideChar(CP_UTF8,0,s.data(),static_cast<int>(s.size()),&w[0],n); return w;
}
std::string utf8(const std::wstring& w) {
    if(w.empty())return "";
    int n=WideCharToMultiByte(CP_UTF8,0,w.data(),static_cast<int>(w.size()),nullptr,0,nullptr,nullptr);
    std::string s(n,'\0'); WideCharToMultiByte(CP_UTF8,0,w.data(),static_cast<int>(w.size()),&s[0],n,nullptr,nullptr); return s;
}
void clearString(std::string& s) { if(!s.empty())SecureZeroMemory(&s[0],s.size()); s.clear(); }
std::wstring number(std::uint64_t n) { return std::to_wstring(static_cast<unsigned long long>(n)); }
std::wstring fixed(double n,int digits=2) { wchar_t b[64]={}; swprintf(b,64,digits==0?L"%.0f":digits==1?L"%.1f":L"%.2f",n);return b; }
std::wstring volume(std::uint64_t n) { return n>=1000000000ULL?fixed(n/1000000000.0)+L" ГБ":fixed(n/1000000.0,1)+L" МБ"; }
std::wstring clockText() { SYSTEMTIME t={};GetLocalTime(&t); wchar_t b[16]={};swprintf(b,16,L"%02u:%02u:%02u",t.wHour,t.wMinute,t.wSecond);return b; }
std::wstring systemError(DWORD code) {
    wchar_t* raw=nullptr; FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,nullptr,code,0,reinterpret_cast<wchar_t*>(&raw),0,nullptr);
    std::wstring s=raw?raw:L""; if(raw)LocalFree(raw); while(!s.empty()&&(s.back()==L'\r'||s.back()==L'\n'))s.pop_back();
    return L"Код "+std::to_wstring(code)+(s.empty()?L"":L": "+s);
}
void alert(const std::wstring& s,UINT flags=MB_ICONERROR) { MessageBoxW(window,s.c_str(),AppName,MB_OK|flags); }
void setBanner(const std::wstring& text,bool error=false) { banner=text;bannerError=error;InvalidateRect(content,nullptr,FALSE); }
std::wstring configError(const std::string& e) {
    if(e=="PORTS")return L"Все включённые порты должны различаться. Допустимы числа от 1 до 65535.";
    if(e=="PROTOCOLS")return L"Включите хотя бы один вход: SOCKS5 / HTTP, цепочку, TLS или локальный DNS.";
    if(e=="UDP_RANGE")return L"Диапазон UDP: укажите порты от 1 до 65535, начальный порт не больше конечного.";
    if(e=="UDP_DNS_CONFLICT")return L"Порт локального DNS должен находиться вне выбранного диапазона SOCKS5 UDP.";
    if(e=="TLS")return L"Для TLS укажите существующие PEM-файлы сертификата и закрытого ключа.";
    if(e=="DNS")return L"DNS: укажите URI udp://host:53, tcp://host:53, tls://host:853 или https://host/dns-query. Допустим домен ASCII или IPv4.";
    if(e=="DNS_REQUIRED")return L"Для локального DNS укажите явный DNS-сервер в поле «DNS-сервер для прокси», например udp://1.1.1.1:53.";
    if(e=="UPSTREAM")return L"Укажите адрес, порт и тип внешнего прокси для цепочки.";
    if(e=="UPSTREAM_AUTH")return L"Для внешнего прокси задайте и логин, и пароль либо оставьте оба поля пустыми.";
    if(e=="UPSTREAM_AUTH_FORMAT")return L"Учётные данные внешнего прокси: до 255 печатных ASCII-символов без пробелов; логин не должен содержать двоеточие.";
    if(e=="UPSTREAM_LOOP")return L"Внешний прокси не должен указывать обратно на один из портов этой программы.";
    if(e=="USER")return L"Логин: 1–128 печатных ASCII-символов без пробелов и двоеточия. Например: proxyuser.";
    if(e=="PASSWORD")return L"Пароль: 8–255 печатных ASCII-символов без пробелов. Можно нажать «Создать пароль».";
    if(e=="IP")return L"Разрешённый IP: один точный IPv4-адрес клиента или пустое поле.";
    if(e=="BIND")return L"Адрес сервера: IPv4-адрес интерфейса или 0.0.0.0 для всех интерфейсов.";
    if(e=="LIMIT")return L"Лимит соединений: от 1 до 10000.";
    if(e=="TIMEOUT_CONNECT")return L"Тайм-аут подключения: от 1 до 300 секунд.";
    if(e=="TIMEOUT_HTTP")return L"Тайм-аут простоя HTTP: от 1 до 86400 секунд.";
    if(e=="TIMEOUT")return L"Тайм-аут подключения: 1–300 секунд. Простой HTTP: 1–86400 секунд.";
    if(e=="ALREADY_RUNNING")return L"Сервер уже запущен.";
    if(e.find("10048")!=std::string::npos||e.find("address already in use")!=std::string::npos)return L"Порт уже занят. Возможно, работает старая версия прокси. Выберите другие порты или остановите старую программу.\n\n"+wide(e);
    if(e.find("10013")!=std::string::npos)return L"Windows отказала в открытии порта. Порт может быть зарезервирован или занят другим приложением. Попробуйте другой порт.\n\n"+wide(e);
    return L"Не удалось запустить сервер. Проверьте, что выбранные порты свободны, а адрес сервера существует.\n\n"+wide(e);
}

void fill(HDC dc,RECT r,COLORREF c) { HBRUSH b=CreateSolidBrush(c);FillRect(dc,&r,b);DeleteObject(b); }
RECT logicalRect(int x,int y,int w,int h,bool scrolling=false) { RECT r={px(x-(scrolling?scrollX:0)),px(y-(scrolling?scrollY:0)),px(x+w-(scrolling?scrollX:0)),px(y+h-(scrolling?scrollY:0))};return r; }
void drawText(HDC dc,const std::wstring& s,int x,int y,int w,int h,HFONT f,COLORREF color,UINT flags=DT_LEFT|DT_VCENTER|DT_SINGLELINE,bool scrolling=true) {
    HGDIOBJ old=SelectObject(dc,f);SetBkMode(dc,TRANSPARENT);SetTextColor(dc,color);RECT r=logicalRect(x,y,w,h,scrolling);DrawTextW(dc,s.c_str(),static_cast<int>(s.size()),&r,flags);SelectObject(dc,old);
}
void roundRect(HDC dc,int x,int y,int w,int h,COLORREF color,COLORREF outline,int radius=12,bool scrolling=true) {
    HBRUSH b=CreateSolidBrush(color);HPEN p=CreatePen(PS_SOLID,1,outline);HGDIOBJ ob=SelectObject(dc,b),op=SelectObject(dc,p);
    RECT r=logicalRect(x,y,w,h,scrolling);RoundRect(dc,r.left,r.top,r.right,r.bottom,px(radius),px(radius));SelectObject(dc,ob);SelectObject(dc,op);DeleteObject(b);DeleteObject(p);
}
void line(HDC dc,int x1,int y1,int x2,int y2,COLORREF color,int width=1,bool scrolling=true) {
    HPEN p=CreatePen(PS_SOLID,px(width),color);HGDIOBJ old=SelectObject(dc,p);int off=scrolling?scrollY:0,offx=scrolling?scrollX:0;MoveToEx(dc,px(x1-offx),px(y1-off),nullptr);LineTo(dc,px(x2-offx),px(y2-off));SelectObject(dc,old);DeleteObject(p);
}
void dot(HDC dc,int x,int y,int radius,COLORREF color,bool scrolling=true) {
    HBRUSH b=CreateSolidBrush(color);HGDIOBJ ob=SelectObject(dc,b),op=SelectObject(dc,GetStockObject(NULL_PEN));int off=scrolling?scrollY:0,offx=scrolling?scrollX:0;Ellipse(dc,px(x-offx-radius),px(y-off-radius),px(x-offx+radius),px(y-off+radius));SelectObject(dc,ob);SelectObject(dc,op);DeleteObject(b);
}
void card(HDC dc,int y,int h) { roundRect(dc,Margin,y,contentWidth-Margin*2,h,White,Border); }
void drawSectionTitle(HDC dc,const std::wstring& s,int y) { drawText(dc,s,Margin+20,y,contentWidth-2*Margin-40,26,fonts.medium,Text); }
void drawGraph(HDC dc) {
    const int x=Margin+20,y=364,w=contentWidth-2*Margin-92,h=110;
    double ceiling=.5;
    for(double v:uploadHistory)ceiling=(std::max)(ceiling,v);
    for(double v:downloadHistory)ceiling=(std::max)(ceiling,v);
    ceiling=std::ceil(ceiling*1.15*2)/2;
    for(int i=0;i<4;++i) {
        int yy=y+h*i/3;line(dc,x,yy,x+w,yy,RGB(235,239,245));
        drawText(dc,fixed(ceiling*(3-i)/3,1),x+w+10,yy-10,50,20,fonts.small,Muted);
    }
    if(!latest.metricsAvailable){drawText(dc,L"Ожидаем данные счётчиков",x,y+h/2-12,w,24,fonts.small,Muted,DT_CENTER|DT_SINGLELINE|DT_VCENTER);return;}
    auto series=[&](const std::deque<double>& points,COLORREF color) {
        if(points.size()<2)return;
        HPEN p=CreatePen(PS_SOLID,px(2),color);HGDIOBJ op=SelectObject(dc,p);
        std::size_t skip=60-points.size();
        for(std::size_t i=0;i<points.size();++i) {
            int xx=x+static_cast<int>((skip+i)*w/59);int yy=y+h-static_cast<int>((std::min)(points[i]/ceiling,1.0)*h);
            if(i)LineTo(dc,px(xx-scrollX),px(yy-scrollY));else MoveToEx(dc,px(xx-scrollX),px(yy-scrollY),nullptr);
        }
        SelectObject(dc,op);DeleteObject(p);
    };
    series(downloadHistory,Blue);series(uploadHistory,Green);
    drawText(dc,L"60 последних замеров",x,y+h+6,140,20,fonts.small,Muted);
    drawText(dc,L"Мбит/с",x+w+4,y-24,60,20,fonts.small,Muted);
    drawText(dc,L"Без MTProto",x+150,y+h+6,160,20,fonts.small,Muted);
    drawText(dc,L"Сейчас",x+w-90,y+h+6,90,20,fonts.small,Muted,DT_RIGHT|DT_SINGLELINE|DT_VCENTER);
}
void paintOverview(HDC dc) {
    bool on=proxyRunning();
    bool ready=on&&!serviceMutationBusy()&&latest.metricsAvailable&&latest.expectedServices>0&&latest.readyServices==latest.expectedServices&&latest.failedServices==0;
    card(dc,106,66);dot(dc,Margin+24,139,5,ready?Green:on?RGB(218,154,51):Muted);
    std::wstring state=serviceMode()&&serviceMutationBusy()?L"Выполняется операция службы":engineStateUnknown()?L"Состояние прокси неизвестно":!on?L"Прокси остановлен":ready?L"Компонент прокси работает":latest.failedServices?L"Есть недоступные порты":L"Прокси запускается";
    drawText(dc,state,Margin+42,116,contentWidth-2*Margin-70,25,fonts.medium,Text);
    drawText(dc,engineStateUnknown()?L"Ожидаем данные службы; состояние подключений не подтверждено":ready?L"Доступность настроенных портов проверьте из клиента":on?L"Проверяем состояние компонентов и слушателей":L"Запуск и остановка доступны одной кнопкой",Margin+42,142,contentWidth-2*Margin-70,18,fonts.small,Muted);
    int gap=16,half=(contentWidth-2*Margin-gap)/2;
    roundRect(dc,Margin,188,half,96,White,Border);roundRect(dc,Margin+half+gap,188,half,96,White,Border);
    auto endpoint=[&](int x,bool enabled,const wchar_t* name,unsigned port,std::uint64_t sessions) {
        drawText(dc,name,x+20,199,half-100,25,fonts.medium,Text);
        dot(dc,x+half-23,211,4,on&&enabled?(ready?Green:RGB(218,154,51)):Muted);
        drawText(dc,enabled?std::to_wstring(port):L"Выкл.",x+20,227,140,36,fonts.number,enabled?Text:Muted);
        drawText(dc,L"Запросов: "+(latest.metricsAvailable?number(sessions):L"—"),x+153,235,half-173,20,fonts.small,Muted);
        drawText(dc,enabled?((std::wstring(name)==L"SOCKS5"&&configured.enableSocksUdp?L"TCP + UDP · ":L"TCP · ")+wide(configured.bindAddress)):L"Протокол отключён",x+20,264,half-40,18,fonts.small,Muted);
    };
    endpoint(Margin,configured.enableSocks,L"SOCKS5",configured.socksPort,latest.socks);
    endpoint(Margin+half+gap,configured.enableHttp,L"HTTP / CONNECT",configured.httpPort,latest.http);
    card(dc,302,210);drawSectionTitle(dc,L"Трафик прокси",317);
    int lx=contentWidth-Margin-315;
    dot(dc,lx,332,4,Blue);drawText(dc,L"К клиентам  "+(latest.metricsAvailable?fixed(downloadMbps):L"—")+L" Мбит/с",lx+11,320,285,20,fonts.small,Text);
    dot(dc,lx,352,4,Green);drawText(dc,L"К интернету  "+(latest.metricsAvailable?fixed(uploadMbps):L"—")+L" Мбит/с",lx+11,340,285,20,fonts.small,Text);
    drawGraph(dc);
    int col=(contentWidth-2*Margin-32)/3;
    for(int i=0;i<3;++i)roundRect(dc,Margin+i*(col+16),528,col,99,White,Border);
    drawText(dc,L"Активные",Margin+18,540,col-36,20,fonts.small,Muted);
    drawText(dc,latest.metricsAvailable?number(latest.active):L"—",Margin+18,564,col-70,34,fonts.number,Text);
    drawText(dc,L"в обработке",Margin+18,601,col-36,18,fonts.small,Muted);
    int x=Margin+col+16;
    drawText(dc,L"Запросов",x+18,540,col-36,20,fonts.small,Muted);
    drawText(dc,latest.metricsAvailable?number(latest.accepted):L"—",x+18,564,col-36,34,fonts.number,Text);
    drawText(dc,L"с момента запуска",x+18,601,col-36,18,fonts.small,Muted);
    x+=col+16;
    drawText(dc,L"Трафик к клиентам",x+18,540,col-36,20,fonts.small,Muted);
    drawText(dc,latest.metricsAvailable?volume(latest.received):L"—",x+18,564,col-36,34,fonts.number,Text);
    drawText(dc,L"К интернету: "+(latest.metricsAvailable?volume(latest.sent):L"—"),x+18,601,col-36,18,fonts.small,Muted);
    std::wstring foot=configured.user.empty()?L"Первый запуск: откройте «Настройки» и задайте логин и пароль.":L"Учётная запись: "+wide(configured.user)+L"   ·   "+(configured.allowIp.empty()?L"Любой IP, с авторизацией":L"Только "+wide(configured.allowIp));
    drawText(dc,foot,Margin,642,contentWidth-2*Margin,26,fonts.small,Muted);
    int extraY=684;
    if(configured.enableHttps||configured.enableSocksTls||configured.enableDns) {
        card(dc,extraY,78);drawText(dc,L"TLS и DNS",Margin+20,extraY+12,contentWidth-2*Margin-40,24,fonts.medium,Text);
        std::wstring endpoints;
        if(configured.enableHttps)endpoints=L"HTTPS :"+std::to_wstring(configured.httpsPort);
        if(configured.enableSocksTls)endpoints+=(endpoints.empty()?L"":L"   ·   ")+std::wstring(L"SOCKS/TLS :")+std::to_wstring(configured.socksTlsPort);
        if(configured.enableDns)endpoints+=(endpoints.empty()?L"":L"   ·   ")+std::wstring(L"DNS 127.0.0.1:")+std::to_wstring(configured.dnsPort);
        drawText(dc,endpoints,Margin+20,extraY+44,contentWidth-2*Margin-40,23,fonts.normal,Text);extraY+=94;
    }
    if(configured.enableChainSocks||configured.enableChainHttp) {
        card(dc,extraY,92);
        drawText(dc,L"Цепочка через внешний прокси",Margin+20,extraY+12,contentWidth-2*Margin-40,22,fonts.medium,Text);
        std::wstring endpoints=(configured.enableChainSocks?L"SOCKS5 :"+std::to_wstring(configured.chainSocksPort):L"")+
          (configured.enableChainSocks&&configured.enableChainHttp?L"    ·    ":L"")+
          (configured.enableChainHttp?L"HTTP :"+std::to_wstring(configured.chainHttpPort):L"");
        drawText(dc,endpoints+L"  →  "+wide(configured.upstreamHost)+L":"+std::to_wstring(configured.upstreamPort),Margin+20,extraY+41,contentWidth-2*Margin-40,22,fonts.normal,Text);
        drawText(dc,L"Запросов цепочки: "+(latest.metricsAvailable?number(latest.chainSocks+latest.chainHttp):L"—"),Margin+20,extraY+66,contentWidth-2*Margin-40,19,fonts.small,Muted);
    }
    if(configured.enableChainSocks||configured.enableChainHttp)extraY+=108;
    int mtY=extraY;
    if(!mtConfigured.secret.empty()) {
        card(dc,mtY,78);dot(dc,Margin+25,mtY+26,4,telegramRunning()&&!serviceMutationBusy()?Green:Muted);
        drawText(dc,L"Telegram / MTProto",Margin+42,mtY+13,contentWidth-2*Margin-60,24,fonts.medium,Text);
        drawText(dc,(engineStateUnknown()?L"Состояние неизвестно":telegramRunning()?L"Процесс работает":L"Остановлен")+std::wstring(L"   ·   TCP ")+std::to_wstring(mtConfigured.listenPort)+L"   ·   Отдельный сервис",Margin+20,mtY+44,contentWidth-2*Margin-40,21,fonts.small,Muted);
    }
    int messageY=!mtConfigured.secret.empty()?mtY+96:extraY>684?extraY+2:679;
    if(!banner.empty())drawText(dc,banner,Margin,messageY,contentWidth-2*Margin,48,fonts.normal,bannerError?Red:Green,DT_LEFT|DT_WORDBREAK);
}
void paintSettings(HDC dc) {
    int inner=contentWidth-2*Margin-40,half=(inner-20)/2,left=Margin+20,right=left+half+20;
    card(dc,106,174);drawSectionTitle(dc,L"Учётная запись",121);
    drawText(dc,L"Логин",left,155,half,22,fonts.small,Muted);
    drawText(dc,L"Пароль",right,155,half,22,fonts.small,Muted);
    drawText(dc,L"Единый вход для SOCKS5 / HTTP / TLS. Пароли защищены Windows DPAPI.",left,247,inner,20,fonts.small,Muted);
    card(dc,296,203);drawSectionTitle(dc,L"Подключения",311);
    drawText(dc,L"Порт",left+half-98,342,98,20,fonts.small,Muted);
    drawText(dc,L"Порт",right+half-98,342,98,20,fonts.small,Muted);
    drawText(dc,L"Адрес сервера",left,408,half,21,fonts.small,Muted);
    drawText(dc,L"Разрешённый IP клиента",right,408,half,21,fonts.small,Muted);
    drawText(dc,L"0.0.0.0 — все сетевые интерфейсы",left,470,half,20,fonts.small,Muted);
    drawText(dc,L"Пустое поле — любой IP с авторизацией",right,470,half,20,fonts.small,Muted);
    card(dc,515,154);drawSectionTitle(dc,L"Запуск и окно",530);
    card(dc,685,111);drawSectionTitle(dc,L"Ограничения",700);
    int third=(inner-32)/3;
    drawText(dc,L"Соединений, максимум",left,734,third,20,fonts.small,Muted);
    drawText(dc,L"Подключение, секунд",left+third+16,734,third,20,fonts.small,Muted);
    drawText(dc,L"Простой HTTP, сек",left+2*(third+16),734,third,20,fonts.small,Muted);
    std::wstring message=proxyRunning()?L"Чтобы изменить параметры подключения, остановите сервер.":dirty?L"Есть несохранённые изменения.":(serviceMode()?L"Настройки сохраняются в защищённом профиле службы.":L"Настройки сохраняются в proxy.ini рядом с программой.");
    drawText(dc,message,Margin,815,contentWidth-2*Margin,23,fonts.small,proxyRunning()?Muted:dirty?Blue:Muted);
    if(!banner.empty())drawText(dc,banner,Margin,900,contentWidth-2*Margin,48,fonts.normal,bannerError?Red:Green,DT_LEFT|DT_WORDBREAK);
}
void paintChain(HDC dc) {
    int left=Margin+20,inner=contentWidth-2*Margin-40,half=(inner-20)/2,right=left+half+20;
    card(dc,106,78);
    drawText(dc,L"Клиент  →  ваш VDS  →  внешний прокси  →  интернет",left,118,inner,25,fonts.medium,Text);
    drawText(dc,L"Прямые порты продолжают работать отдельно. Дополнительные порты включаются ниже.",left,148,inner,23,fonts.small,Muted);
    card(dc,200,147);drawSectionTitle(dc,L"Порты входа в цепочку",215);
    drawText(dc,L"Порт",left+half-98,246,98,20,fonts.small,Muted);
    drawText(dc,L"Порт",right+half-98,246,98,20,fonts.small,Muted);
    drawText(dc,L"Для входа используются логин, пароль и разрешённый IP из основных настроек.",left,316,inner,22,fonts.small,Muted);
    card(dc,363,241);drawSectionTitle(dc,L"Внешний прокси",378);
    int typeWidth=150,portWidth=96,hostX=left+typeWidth+16,hostWidth=inner-typeWidth-portWidth-32,portX=hostX+hostWidth+16;
    drawText(dc,L"Тип",left,412,typeWidth,22,fonts.small,Muted);
    drawText(dc,L"Адрес сервера",hostX,412,hostWidth,22,fonts.small,Muted);
    drawText(dc,L"Порт",portX,412,portWidth,22,fonts.small,Muted);
    drawText(dc,L"Логин внешнего прокси",left,484,half,22,fonts.small,Muted);
    drawText(dc,L"Пароль внешнего прокси",right,484,half,22,fonts.small,Muted);
    drawText(dc,L"Без авторизации: оставьте логин и пароль внешнего прокси пустыми.",left,574,inner,22,fonts.small,Muted);
    card(dc,620,82);
    drawText(dc,L"При недоступности внешнего прокси цепочка прекращает подключение.",left,632,inner,23,fonts.normal,Text);
    drawText(dc,L"Автоматического перехода на прямое соединение нет.",left,663,inner,22,fonts.small,Muted);
    drawText(dc,proxyRunning()?L"Для изменения цепочки остановите сервер.":dirty?L"Есть несохранённые изменения.":L"Пароль внешнего прокси хранится с защитой Windows DPAPI.",Margin,718,contentWidth-2*Margin,23,fonts.small,dirty?Blue:Muted);
    if(!banner.empty())drawText(dc,banner,Margin,805,contentWidth-2*Margin,48,fonts.normal,bannerError?Red:Green,DT_LEFT|DT_WORDBREAK);
}
void paintTlsDns(HDC dc) {
    int left=Margin+20,inner=contentWidth-2*Margin-40,half=(inner-20)/2,right=left+half+20;
    card(dc,106,346);drawSectionTitle(dc,L"Шифрование канала до прокси",121);
    drawText(dc,L"Порт",left+half-98,155,98,20,fonts.small,Muted);drawText(dc,L"Порт",right+half-98,155,98,20,fonts.small,Muted);
    drawText(dc,L"Сертификат TLS (PEM)",left,216,inner,20,fonts.small,Muted);
    drawText(dc,L"Закрытый ключ TLS (PEM)",left,279,inner,20,fonts.small,Muted);
    drawText(dc,L"Имя в новом сертификате: публичный IP VDS или домен",left,342,inner,20,fonts.small,Muted);
    card(dc,468,215);drawSectionTitle(dc,L"DNS",483);
    drawText(dc,L"DNS-сервер для прокси",left,515,inner,20,fonts.small,Muted);
    drawText(dc,L"Пусто — системный DNS прокси. Для локального DNS укажите URI.",left,574,inner,20,fonts.small,Muted);
    drawText(dc,L"Порт",left+inner-98,598,98,20,fonts.small,Muted);
    drawText(dc,L"Локальный DNS всегда слушает только 127.0.0.1 по TCP и UDP.",left,655,inner,20,fonts.small,Muted);
    card(dc,699,168);drawSectionTitle(dc,L"UDP для SOCKS5",714);
    drawText(dc,L"UDP-диапазон",left,774,135,22,fonts.small,Muted);drawText(dc,L"—",left+236,774,24,24,fonts.normal,Muted);
    drawText(dc,L"UDP-датаграммы не шифруются TLS-контролем; внешний SOCKS5 должен поддерживать UDP.",left,810,inner,45,fonts.small,Muted,DT_LEFT|DT_WORDBREAK);
    drawText(dc,proxyRunning()?L"Для изменения TLS, DNS и UDP остановите прокси.":dirty?L"Есть несохранённые изменения.":L"TLS использует ту же учётную запись и правило доступа по IP, что SOCKS5 / HTTP.",Margin,887,contentWidth-2*Margin,30,fonts.small,dirty?Blue:Muted,DT_LEFT|DT_WORDBREAK);
    if(!banner.empty())drawText(dc,banner,Margin,978,contentWidth-2*Margin,67,fonts.normal,bannerError?Red:Green,DT_LEFT|DT_WORDBREAK);
}
void paintTelegram(HDC dc) {
    const int left=Margin+20,inner=contentWidth-2*Margin-40;
    card(dc,106,79);dot(dc,left+4,130,4,telegramRunning()&&!serviceMutationBusy()?Green:Muted);
    drawText(dc,serviceMode()&&serviceMutationBusy()?L"Выполняется операция службы":engineStateUnknown()?L"Состояние MTProto неизвестно":telegramRunning()?L"Процесс MTProto работает":L"MTProto остановлен",left+20,117,inner-190,25,fonts.medium,Text);
    drawText(dc,L"Отдельный сервис для Telegram. Работает независимо от SOCKS5 / HTTP.",left,157,inner,22,fonts.small,Muted);
    card(dc,201,259);drawSectionTitle(dc,L"Подключение Telegram",216);
    drawText(dc,L"Адрес прослушивания",left,253,inner-130,22,fonts.small,Muted);drawText(dc,L"TCP-порт",left+inner-110,253,110,22,fonts.small,Muted);
    drawText(dc,L"Внешний IP или домен VDS — для ссылки подключения",left,324,inner,22,fonts.small,Muted);
    drawText(dc,L"Домен FakeTLS — укажите доступный HTTPS-сайт",left,396,inner,22,fonts.small,Muted);
    card(dc,476,178);drawSectionTitle(dc,L"Секрет подключения",491);
    drawText(dc,L"Создайте секрет для выбранного домена. Это отдельный ключ, без логина и пароля.",left,522,inner,22,fonts.small,Muted);
    card(dc,670,96);
    drawText(dc,L"Для mtg.exe Windows может запросить отдельное разрешение брандмауэра.",left,681,inner,24,fonts.small,Text);
    drawText(dc,L"На MTProto не действует ограничение IP из основных настроек.",left,710,inner,23,fonts.small,Muted);
    drawText(dc,L"Ссылка содержит секрет. Передавайте её только тем, кому разрешён доступ.",left,737,inner,21,fonts.small,Muted);
    drawText(dc,telegramRunning()?L"Для изменения параметров остановите MTProto.":mtDirty?L"Есть несохранённые параметры MTProto.":(serviceMode()?L"Секрет хранится в защищённом профиле службы с Windows DPAPI.":L"Секрет хранится в proxy.ini с защитой Windows DPAPI."),Margin,783,contentWidth-2*Margin,24,fonts.small,mtDirty?Blue:Muted);
    if(!mtBanner.empty())drawText(dc,mtBanner,Margin,871,contentWidth-2*Margin,67,fonts.normal,mtBannerError?Red:Green,DT_LEFT|DT_WORDBREAK);
}
std::wstring serviceStatusText() {
    if(!serviceChecked)return L"Проверяем состояние службы";
    if(!serviceStatusKnown)return L"Состояние службы неизвестно";
    if(!serviceMode())return L"Портативный режим";
    switch(serviceState.scmState) {
      case SERVICE_RUNNING:return serviceState.reachable?L"Служба работает":L"Служба запущена, но связь недоступна";
      case SERVICE_STOPPED:return L"Служба остановлена";
      case SERVICE_START_PENDING:return L"Служба запускается";
      case SERVICE_STOP_PENDING:return L"Служба останавливается";
      case SERVICE_PAUSED:return L"Служба приостановлена";
      default:return L"Служба меняет состояние";
    }
}
void paintService(HDC dc) {
    const int left=Margin+20,inner=contentWidth-2*Margin-40;
    const bool known=serviceStatusKnown&&serviceChecked;
    const COLORREF statusColor=known&&serviceState.reachable&&!serviceMutationBusy()?Green:known&&!serviceMode()?Muted:RGB(218,154,51);
    card(dc,106,218);dot(dc,left+4,132,5,statusColor);
    drawText(dc,serviceStatusText(),left+22,117,inner-22,28,fonts.medium,Text);
    drawText(dc,!known?L"Получаем подтверждённое состояние службы Windows.":serviceMode()?L"Закрытие окна и выход из учётной записи не останавливают службу.":L"Сетевые компоненты работают только пока открыта программа.",left,155,inner,23,fonts.small,Muted);
    std::wstring engines=engineStateUnknown()?L"Состояние компонентов не подтверждено":L"Прокси: "+std::wstring(proxyRunning()?L"работает":L"остановлен")+L"    ·    MTProto: "+(telegramRunning()?L"работает":L"остановлен");
    drawText(dc,engines,left,187,inner,22,fonts.small,Text);
    std::wstring restarts=L"Автоперезапуски: прокси "+(serviceState.reachable?number(serviceState.proxyRestarts):L"—")+L"    ·    MTProto "+(serviceState.reachable?number(serviceState.mtRestarts):L"—");
    drawText(dc,restarts,left,215,inner,20,fonts.small,Muted);
    std::wstring detail;bool detailError=serviceBannerError;
    if(serviceMutationBusy())detail=L"Выполняется операция службы… Окно остаётся доступным.";
    else {
        if(!serviceState.proxyError.empty()){detail=L"Прокси: "+wide(serviceState.proxyError);detailError=true;}
        if(!serviceState.mtError.empty()){if(!detail.empty())detail+=L"\n";detail+=L"MTProto: "+wide(serviceState.mtError);detailError=true;}
        if(!serviceState.error.empty()){if(!detail.empty())detail+=L"\n";detail+=wide(serviceState.error);detailError=true;}
        if(!serviceBanner.empty()&&(detail.empty()||detail.find(serviceBanner)==std::wstring::npos)){if(!detail.empty())detail+=L"\n";detail+=serviceBanner;}
    }
    if(detail.empty())detail=serviceMode()?L"Запуск, остановка и удаление службы доступны ниже.":L"Выберите автозапуск ниже, затем установите службу. Старый proxy.ini останется на месте.";
    drawText(dc,detail,left,242,inner,60,fonts.small,detailError?Red:Muted,DT_LEFT|DT_WORDBREAK|DT_END_ELLIPSIS);
    if(detailError)drawText(dc,L"Подробности ошибок — на вкладке «Журнал».",left,305,inner,16,fonts.small,Muted);
    card(dc,490,194);drawSectionTitle(dc,L"После загрузки Windows",505);
    drawText(dc,serviceMode()?L"Автозапуск компонентов изменяется в «Настройках» и «Telegram».":L"Выберите компоненты для запуска без входа в систему.",left,537,inner,23,fonts.small,Muted);
    card(dc,700,180);drawSectionTitle(dc,L"Отдельно от окна программы",715);
    drawText(dc,L"Служба работает от LocalSystem. Программа и компоненты копируются в защищённую папку Program Files; профиль хранится в ProgramData.",left,750,inner,59,fonts.normal,Text,DT_LEFT|DT_WORDBREAK);
    drawText(dc,L"Пароль Windows не нужен. Разрешение брандмауэра касается только портов службы; другие правила, сетевые профили и RDP не меняются.",left,818,inner,47,fonts.small,Muted,DT_LEFT|DT_WORDBREAK);
    card(dc,896,150);drawSectionTitle(dc,L"Папки службы",911);
    drawText(dc,L"Программа",left,944,inner,19,fonts.small,Muted);
    drawText(dc,serviceState.installDir.empty()?L"Будет создана при установке":serviceState.installDir,left,967,inner,23,fonts.normal,Text,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_PATH_ELLIPSIS);
    drawText(dc,L"Настройки и сертификаты",left,997,inner,19,fonts.small,Muted);
    drawText(dc,serviceState.dataDir.empty()?L"Будет создана при установке":serviceState.dataDir,left,1019,inner,23,fonts.normal,Text,DT_LEFT|DT_VCENTER|DT_SINGLELINE|DT_PATH_ELLIPSIS);
}
void paintJournal(HDC dc) {
    card(dc,106,76);
    drawText(dc,L"Диагностика без содержимого трафика",Margin+20,118,contentWidth-2*Margin-40,25,fonts.medium,Text);
    drawText(dc,L"Пароли и адреса открываемых страниц в журнал не записываются.",Margin+20,146,contentWidth-2*Margin-40,22,fonts.small,Muted);
    std::wstring summary=latest.metricsAvailable?L"Запросов: "+number(latest.accepted)+L"   ·   Ошибки обработки: "+number(latest.handlerErrors)+L"   ·   MTProto учитывается отдельно":L"Ожидаем данные счётчиков; MTProto учитывается отдельно";
    drawText(dc,summary,Margin,202,contentWidth-2*Margin,23,fonts.small,Muted);
    drawText(dc,logWriteFailed?L"Файл журнала недоступен. События можно сохранить кнопкой «Сохранить журнал».":L"Журнал: logs\\ProxyServer.log; предыдущий файл сохраняется при ротации.",Margin,301+(std::max)(335,contentHeight-330),contentWidth-2*Margin,25,fonts.small,logWriteFailed?Red:Muted);
}
void paintContent(HDC dc) {
    RECT client;GetClientRect(content,&client);fill(dc,client,Canvas);
    const wchar_t* titles[]={L"Обзор",L"Настройки",L"Цепочка",L"TLS / DNS",L"Telegram",L"Служба",L"Журнал"};
    const wchar_t* subtitles[]={L"Ваш личный прокси — состояние и трафик в реальном времени",L"Подключения, учётная запись и поведение программы",L"Отдельные входные порты через дополнительный прокси",L"TLS, SOCKS5 UDP и локальный DNS",L"MTProto / FakeTLS — отдельный вход для Telegram",L"Работа после перезагрузки и без входа в Windows",L"Состояние сервера и события подключений"};
    drawText(dc,titles[currentPage],Margin,25,contentWidth-2*Margin-170,34,fonts.title,Text);
    drawText(dc,subtitles[currentPage],Margin,66,contentWidth-2*Margin,23,fonts.small,Muted);
    if(currentPage==Overview)paintOverview(dc);else if(currentPage==Settings)paintSettings(dc);else if(currentPage==Chain)paintChain(dc);else if(currentPage==TlsDns)paintTlsDns(dc);else if(currentPage==Telegram)paintTelegram(dc);else if(currentPage==Service)paintService(dc);else paintJournal(dc);
}
void paintMain(HDC dc) {
    RECT r;GetClientRect(window,&r);fill(dc,r,Dark);
    roundRect(dc,23,27,40,40,Blue,Blue,12,false);
    drawText(dc,L"P",23,25,40,42,fonts.brand,White,DT_CENTER|DT_VCENTER|DT_SINGLELINE,false);
    drawText(dc,L"Proxy",74,27,110,24,fonts.medium,White,DT_LEFT|DT_SINGLELINE,false);
    drawText(dc,L"Server",74,49,110,22,fonts.normal,RGB(172,188,212),DT_LEFT|DT_SINGLELINE,false);
    int h=dip(r.bottom);
    if(h>=650){drawText(dc,L"ЛИЧНЫЙ СЕРВЕР",24,101,160,20,fonts.small,RGB(132,151,178),DT_LEFT|DT_SINGLELINE,false);line(dc,24,h-153,Sidebar-24,h-153,RGB(49,64,87),1,false);drawText(dc,L"Версия 2.1",24,h-143,160,21,fonts.small,RGB(153,172,198),DT_LEFT|DT_SINGLELINE,false);}
}
void drawButton(const DRAWITEMSTRUCT* dis) {
    int id=static_cast<int>(dis->CtlID);HWND h=dis->hwndItem;bool disabled=(dis->itemState&ODS_DISABLED)!=0,pressed=(dis->itemState&ODS_SELECTED)!=0,focus=(dis->itemState&ODS_FOCUS)!=0;
    bool isNav=id>=NavOverview&&id<=NavJournal;bool side=isNav||id==Help||id==Exit;bool selected=isNav&&(id-NavOverview)==static_cast<int>(currentPage);
    bool primary=id==SaveStart||(id==Toggle&&!proxyRunning())||(id==MtToggle&&!telegramRunning())||id==ServiceInstall;
    COLORREF bg=side?(selected?DarkHover:Dark):primary?Blue:White;
    COLORREF fg=side?(selected?White:RGB(183,199,221)):primary?White:Text;
    if(disabled){bg=side?Dark:RGB(232,237,244);fg=RGB(150,160,175);}else if(pressed)bg=side?RGB(52,72,102):primary?RGB(26,82,179):RGB(231,238,248);
    RECT r=dis->rcItem;fill(dis->hDC,r,side?Dark:Canvas);
    HBRUSH b=CreateSolidBrush(bg);HPEN p=CreatePen(PS_SOLID,1,side?bg:primary?bg:Border);HGDIOBJ ob=SelectObject(dis->hDC,b),op=SelectObject(dis->hDC,p);
    RoundRect(dis->hDC,r.left,r.top,r.right,r.bottom,px(9),px(9));SelectObject(dis->hDC,ob);SelectObject(dis->hDC,op);DeleteObject(b);DeleteObject(p);
    if(selected){RECT accent=r;accent.left+=px(1);accent.right=accent.left+px(3);accent.top+=px(12);accent.bottom-=px(12);fill(dis->hDC,accent,RGB(92,159,255));}
    auto caption=getText(h);HGDIOBJ old=SelectObject(dis->hDC,fonts.normal);SetBkMode(dis->hDC,TRANSPARENT);SetTextColor(dis->hDC,fg);
    RECT t=r;t.left+=px(side?18:10);t.right-=px(10);DrawTextW(dis->hDC,caption.c_str(),-1,&t,DT_VCENTER|DT_SINGLELINE|(side?DT_LEFT:DT_CENTER));SelectObject(dis->hDC,old);
    if(focus){RECT f=r;InflateRect(&f,-px(4),-px(4));DrawFocusRect(dis->hDC,&f);}
}

void layoutContent();
LRESULT CALLBACK focusControlProc(HWND hwnd,UINT message,WPARAM wp,LPARAM lp,UINT_PTR subclass,DWORD_PTR) {
    if(message==WM_SETFOCUS&&content) {
        RECT r;GetWindowRect(hwnd,&r);MapWindowPoints(nullptr,content,reinterpret_cast<POINT*>(&r),2);
        int top=dip(r.top),bottom=dip(r.bottom),left=dip(r.left),right=dip(r.right);
        int beforeY=scrollY,beforeX=scrollX;
        if(top<8)scrollY=(std::max)(0,scrollY+top-12);else if(bottom>contentHeight-8)scrollY+=bottom-contentHeight+12;
        if(left<8)scrollX=(std::max)(0,scrollX+left-12);else if(right>viewportWidth-8)scrollX+=right-viewportWidth+12;
        if(beforeY!=scrollY||beforeX!=scrollX)layoutContent();
    }
    if(message==WM_NCDESTROY)RemoveWindowSubclass(hwnd,focusControlProc,subclass);
    return DefSubclassProc(hwnd,message,wp,lp);
}
HWND createControl(const wchar_t* cls,const wchar_t* title,DWORD style,int id,Page page,bool common=false,DWORD ex=0) {
    HWND h=CreateWindowExW(ex,cls,title,WS_CHILD|WS_VISIBLE|style,0,0,1,1,content,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),instance,nullptr);
    SendMessageW(h,WM_SETFONT,reinterpret_cast<WPARAM>(fonts.normal),TRUE);SetWindowSubclass(h,focusControlProc,1,0);controls.push_back({h,id,page,common});return h;
}
void createEdit(int id,int limit,DWORD extra=0,Page page=Settings) {
    HWND h=createControl(L"EDIT",L"",WS_TABSTOP|ES_AUTOHSCROLL|extra,id,page,false,WS_EX_CLIENTEDGE);
    SendMessageW(h,EM_SETLIMITTEXT,limit,0);SendMessageW(h,EM_SETMARGINS,EC_LEFTMARGIN|EC_RIGHTMARGIN,MAKELPARAM(px(8),px(8)));
}
void createCheck(int id,const wchar_t* caption,Page page=Settings) { createControl(L"BUTTON",caption,WS_TABSTOP|BS_AUTOCHECKBOX,id,page); }
void createButton(int id,const wchar_t* caption,Page page,bool common=false) { createControl(L"BUTTON",caption,WS_TABSTOP|BS_OWNERDRAW,id,page,common); }
void place(int id,int x,int y,int w,int h) { HWND v=control(id);MoveWindow(v,px(x-scrollX),px(y-scrollY),px(w),px(h),TRUE); }
void layoutContent();
void selectPage(Page p) {
    if(p==Service&&!serviceMode()&&serviceChecked&&!serviceOptionsDirty)refreshServiceDefaults();
    currentPage=p;scrollY=0;scrollX=0;layoutContent();
    for(HWND h:nav)InvalidateRect(h,nullptr,TRUE);
    InvalidateRect(content,nullptr,TRUE);
}
void layoutContent() {
    if(!content)return;
    RECT rc;GetClientRect(content,&rc);viewportWidth=dip(rc.right);contentWidth=(std::max)(660,viewportWidth);contentHeight=dip(rc.bottom);
    int overviewHeight=(configured.enableChainSocks||configured.enableChainHttp?854:738)+(!mtConfigured.secret.empty()?100:0)+((configured.enableHttps||configured.enableSocksTls||configured.enableDns)?94:0);
    int total=currentPage==Settings?958:currentPage==Chain?865:currentPage==TlsDns?1066:currentPage==Telegram?958:currentPage==Overview?overviewHeight:currentPage==Service?1076:(std::max)(690,contentHeight);
    SCROLLINFO si={};si.cbSize=sizeof(si);si.fMask=SIF_RANGE|SIF_PAGE|SIF_POS;si.nMin=0;si.nMax=total-1;si.nPage=static_cast<UINT>(contentHeight);scrollY=(std::max)(0,(std::min)(scrollY,total-contentHeight));si.nPos=scrollY;SetScrollInfo(content,SB_VERT,&si,TRUE);
    GetClientRect(content,&rc);viewportWidth=dip(rc.right);contentWidth=(std::max)(660,viewportWidth);
    SCROLLINFO sx={};sx.cbSize=sizeof(sx);sx.fMask=SIF_RANGE|SIF_PAGE|SIF_POS;sx.nMin=0;sx.nMax=contentWidth-1;sx.nPage=static_cast<UINT>(viewportWidth);scrollX=(std::max)(0,(std::min)(scrollX,contentWidth-viewportWidth));sx.nPos=scrollX;SetScrollInfo(content,SB_HORZ,&sx,TRUE);
    GetClientRect(content,&rc);contentHeight=dip(rc.bottom);si.nPage=static_cast<UINT>(contentHeight);scrollY=(std::max)(0,(std::min)(scrollY,total-contentHeight));si.nPos=scrollY;SetScrollInfo(content,SB_VERT,&si,TRUE);
    for(const auto& c:controls)ShowWindow(c.hwnd,c.common||c.page==currentPage||((currentPage==Chain||currentPage==TlsDns)&&(c.id==Save||c.id==SaveStart||c.id==OpenFolder))?SW_SHOW:SW_HIDE);
    place(Toggle,contentWidth-Margin-170,29,170,38);
    int left=Margin+20,inner=contentWidth-2*Margin-40,half=(inner-20)/2,right=left+half+20;
    place(User,left,180,half,32);place(Password,right,180,half,32);
    place(ShowPassword,right,218,103,24);place(GeneratePassword,right+112,215,half-112,30);
    place(EnableSocks,left,366,half-110,30);place(SocksPort,left+half-98,363,98,32);
    place(EnableHttp,right,366,half-110,30);place(HttpPort,right+half-98,363,98,32);
    place(BindAddress,left,432,half,32);place(AllowIp,right,432,half,32);
    place(AutoProxy,left,565,inner,25);place(AutoWindows,left,599,inner,25);place(CloseTray,left,633,inner,25);
    int third=(inner-32)/3;
    place(MaxConnections,left,757,third,30);place(ConnectTimeout,left+third+16,757,third,30);place(IdleTimeout,left+2*(third+16),757,third,30);
    int saveY=currentPage==Chain?754:currentPage==TlsDns?926:849;
    place(Save,Margin,saveY,145,38);place(SaveStart,Margin+159,saveY,215,38);place(OpenFolder,contentWidth-Margin-175,saveY,175,38);
    place(EnableChainSocks,left,270,half-110,30);place(ChainSocksPort,left+half-98,267,98,32);
    place(EnableChainHttp,right,270,half-110,30);place(ChainHttpPort,right+half-98,267,98,32);
    int typeWidth=150,portWidth=96,hostX=left+typeWidth+16,hostWidth=inner-typeWidth-portWidth-32,portX=hostX+hostWidth+16;
    place(UpstreamType,left,437,typeWidth,180);place(UpstreamHost,hostX,437,hostWidth,32);place(UpstreamPort,portX,437,portWidth,32);
    place(UpstreamUser,left,509,half,32);place(UpstreamPassword,right,509,half,32);place(ShowUpstreamPassword,right,548,half,24);
    place(EnableHttps,left,180,half-110,30);place(HttpsPort,left+half-98,177,98,32);place(EnableSocksTls,right,180,half-110,30);place(SocksTlsPort,right+half-98,177,98,32);
    place(TlsCert,left,239,inner-104,32);place(BrowseTlsCert,left+inner-92,239,92,32);place(TlsKey,left,302,inner-104,32);place(BrowseTlsKey,left+inner-92,302,92,32);
    place(TlsCertHost,left,365,inner-214,32);place(GenerateTlsCert,left+inner-202,365,202,32);place(TlsUseChain,left,413,inner,25);
    place(DnsServer,left,539,inner,32);place(EnableDns,left,619,inner-110,25);place(DnsPort,left+inner-98,619,98,30);place(SocksUdp,left,744,inner,25);
    place(UdpPortMin,left+137,772,95,30);place(UdpPortMax,left+264,772,95,30);
    place(MtBind,left,277,inner-126,32);place(MtPort,left+inner-110,277,110,32);place(MtPublicHost,left,348,inner,32);place(MtDomain,left,420,inner,32);
    place(MtSecret,left,552,inner,32);place(MtShowSecret,left,593,165,26);place(MtGenerate,left+183,590,182,34);
    place(MtAuto,left,628,inner,23);place(MtToggle,contentWidth-Margin-182,116,162,38);
    place(MtSave,Margin,823,145,38);place(MtCopyLink,Margin+159,823,230,38);
    place(ServiceProxyAuto,left,569,inner,25);place(ServiceMtAuto,left,602,inner,25);place(ServiceFirewall,left,635,inner,25);
    int serviceHalf=(inner-16)/2;
    place(ServiceInstall,left,336,serviceHalf,38);place(ServiceRefresh,left+serviceHalf+16,336,serviceHalf,38);
    place(ServiceStart,left,386,serviceHalf,38);place(ServiceStop,left+serviceHalf+16,386,serviceHalf,38);
    place(ServiceRemove,left,436,serviceHalf,38);place(ServiceOpenData,left+serviceHalf+16,436,serviceHalf,38);
    int listHeight=(std::max)(335,contentHeight-330);
    place(ExportLog,Margin,239,170,36);place(CopyLog,Margin+184,239,170,36);
    MoveWindow(logList,px(Margin-scrollX),px(291-scrollY),px(contentWidth-2*Margin),px(listHeight),TRUE);
    ShowWindow(logList,currentPage==Journal?SW_SHOW:SW_HIDE);
    ListView_SetColumnWidth(logList,0,px(82));ListView_SetColumnWidth(logList,1,px(97));ListView_SetColumnWidth(logList,2,px((std::max)(280,contentWidth-2*Margin-199)));
    InvalidateRect(content,nullptr,TRUE);
}
void layoutMain() {
    RECT r;GetClientRect(window,&r);int h=dip(r.bottom);
    int navStart=h>=650?143:h>=550?125:h>=470?104:86;
    int helpTop=h-(h<470?88:111),navStep=(std::min)(46,(std::max)(24,(helpTop-navStart-12)/7)),navHeight=(std::min)(40,navStep-4);
    for(int i=0;i<7;++i)MoveWindow(nav[i],px(14),px(navStart+i*navStep),px(Sidebar-28),px(navHeight),TRUE);
    MoveWindow(helpButton,px(14),px(h-(h<470?88:111)),px(Sidebar-28),px(h<470?34:40),TRUE);MoveWindow(exitButton,px(14),px(h-(h<470?44:65)),px(Sidebar-28),px(h<470?34:40),TRUE);
    MoveWindow(content,px(Sidebar),0,(std::max)(1,static_cast<int>(r.right)-px(Sidebar)),r.bottom,TRUE);layoutContent();InvalidateRect(window,nullptr,TRUE);
}
void createFonts() {
    auto make=[&](int size,int weight)->HFONT{return CreateFontW(-px(size),0,0,0,weight,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH|FF_DONTCARE,L"Segoe UI");};
    fonts.normal=make(14,FW_NORMAL);fonts.small=make(12,FW_NORMAL);fonts.medium=make(16,FW_SEMIBOLD);fonts.title=make(27,FW_SEMIBOLD);fonts.number=make(27,FW_SEMIBOLD);fonts.brand=make(27,FW_BOLD);
}
void deleteFonts() { HFONT f[]={fonts.normal,fonts.small,fonts.medium,fonts.title,fonts.number,fonts.brand};for(HFONT h:f)if(h)DeleteObject(h);fonts=Fonts(); }
void refreshFonts() { for(const auto& c:controls)SendMessageW(c.hwnd,WM_SETFONT,reinterpret_cast<WPARAM>(fonts.normal),TRUE);for(HWND h:nav)SendMessageW(h,WM_SETFONT,reinterpret_cast<WPARAM>(fonts.normal),TRUE);SendMessageW(logList,WM_SETFONT,reinterpret_cast<WPARAM>(fonts.normal),TRUE); }
void createControls() {
    createFonts();
    const wchar_t* navNames[]={L"Обзор",L"Настройки",L"Цепочка",L"TLS / DNS",L"Telegram",L"Служба",L"Журнал"};
    for(int i=0;i<7;++i)nav[i]=CreateWindowExW(0,L"BUTTON",navNames[i],WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_OWNERDRAW,0,0,1,1,window,reinterpret_cast<HMENU>(static_cast<INT_PTR>(NavOverview+i)),instance,nullptr);
    helpButton=CreateWindowExW(0,L"BUTTON",L"Помощь",WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_OWNERDRAW,0,0,1,1,window,reinterpret_cast<HMENU>(Help),instance,nullptr);
    exitButton=CreateWindowExW(0,L"BUTTON",L"Выход",WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_OWNERDRAW,0,0,1,1,window,reinterpret_cast<HMENU>(Exit),instance,nullptr);
    content=CreateWindowExW(WS_EX_CONTROLPARENT,ContentClass,L"",WS_CHILD|WS_VISIBLE|WS_CLIPCHILDREN|WS_VSCROLL|WS_HSCROLL,0,0,1,1,window,nullptr,instance,nullptr);
    createButton(Toggle,L"SOCKS/HTTP: пуск",Overview,true);toggleButton=control(Toggle);
    createEdit(User,128);createEdit(Password,255,ES_PASSWORD);SendMessageW(control(Password),EM_SETPASSWORDCHAR,0x25CF,0);
    createCheck(ShowPassword,L"Показать");createButton(GeneratePassword,L"Создать пароль",Settings);
    createCheck(EnableSocks,L"SOCKS5");createCheck(EnableHttp,L"HTTP / CONNECT");
    createEdit(SocksPort,5,ES_NUMBER);createEdit(HttpPort,5,ES_NUMBER);createEdit(BindAddress,15);createEdit(AllowIp,15);
    createCheck(AutoProxy,L"Запускать прокси при открытии программы");createCheck(AutoWindows,L"Открывать программу при входе в Windows");createCheck(CloseTray,L"Сворачивать в трей при закрытии окна");
    createEdit(MaxConnections,5,ES_NUMBER);createEdit(ConnectTimeout,3,ES_NUMBER);createEdit(IdleTimeout,5,ES_NUMBER);
    createButton(Save,L"Сохранить",Settings);createButton(SaveStart,L"Сохранить и запустить",Settings);createButton(OpenFolder,L"Папка программы",Settings);
    createCheck(EnableChainSocks,L"SOCKS5",Chain);createCheck(EnableChainHttp,L"HTTP / CONNECT",Chain);
    createEdit(ChainSocksPort,5,ES_NUMBER,Chain);createEdit(ChainHttpPort,5,ES_NUMBER,Chain);
    HWND upstreamType=createControl(L"COMBOBOX",L"",WS_TABSTOP|CBS_DROPDOWNLIST|WS_VSCROLL,UpstreamType,Chain);
    SendMessageW(upstreamType,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(L"SOCKS5"));SendMessageW(upstreamType,CB_ADDSTRING,0,reinterpret_cast<LPARAM>(L"HTTP CONNECT"));SendMessageW(upstreamType,CB_SETCURSEL,0,0);
    createEdit(UpstreamHost,253,0,Chain);createEdit(UpstreamPort,5,ES_NUMBER,Chain);createEdit(UpstreamUser,255,0,Chain);createEdit(UpstreamPassword,255,ES_PASSWORD,Chain);
    SendMessageW(control(UpstreamPassword),EM_SETPASSWORDCHAR,0x25CF,0);createCheck(ShowUpstreamPassword,L"Показать пароль",Chain);
    createCheck(EnableHttps,L"HTTPS-прокси",TlsDns);createEdit(HttpsPort,5,ES_NUMBER,TlsDns);createCheck(EnableSocksTls,L"SOCKS5 / TLS",TlsDns);createEdit(SocksTlsPort,5,ES_NUMBER,TlsDns);
    createEdit(TlsCert,32767,0,TlsDns);createEdit(TlsKey,32767,0,TlsDns);createButton(BrowseTlsCert,L"Обзор…",TlsDns);createButton(BrowseTlsKey,L"Обзор…",TlsDns);createEdit(TlsCertHost,253,0,TlsDns);createButton(GenerateTlsCert,L"Создать сертификат",TlsDns);createCheck(TlsUseChain,L"Направлять TLS-порты через внешний прокси из «Цепочки»",TlsDns);
    createEdit(DnsServer,2048,0,TlsDns);createCheck(EnableDns,L"Локальный DNS: 127.0.0.1",TlsDns);createEdit(DnsPort,5,ES_NUMBER,TlsDns);createCheck(SocksUdp,L"Разрешить SOCKS5 UDP ASSOCIATE",TlsDns);createEdit(UdpPortMin,5,ES_NUMBER,TlsDns);createEdit(UdpPortMax,5,ES_NUMBER,TlsDns);
    createEdit(MtBind,15,0,Telegram);createEdit(MtPort,5,ES_NUMBER,Telegram);createEdit(MtPublicHost,253,0,Telegram);createEdit(MtDomain,253,0,Telegram);createEdit(MtSecret,1024,ES_PASSWORD,Telegram);
    SendMessageW(control(MtSecret),EM_SETPASSWORDCHAR,0x25CF,0);createCheck(MtShowSecret,L"Показать секрет",Telegram);createButton(MtGenerate,L"Создать секрет",Telegram);createCheck(MtAuto,L"Запускать MTProto при открытии программы",Telegram);
    createButton(MtSave,L"Сохранить",Telegram);createButton(MtToggle,L"Запустить",Telegram);createButton(MtCopyLink,L"Скопировать ссылку",Telegram);
    createCheck(ServiceProxyAuto,L"Запускать SOCKS / HTTP / TLS при загрузке Windows",Service);
    createCheck(ServiceMtAuto,L"Запускать MTProto при загрузке Windows",Service);
    createCheck(ServiceFirewall,L"Разрешить выбранные порты службы в брандмауэре",Service);check(ServiceFirewall,true);
    createButton(ServiceInstall,L"Установить службу",Service);createButton(ServiceRefresh,L"Обновить профиль",Service);
    createButton(ServiceStart,L"Запустить службу",Service);createButton(ServiceStop,L"Остановить службу",Service);
    createButton(ServiceRemove,L"Удалить службу",Service);createButton(ServiceOpenData,L"Скопировать путь к данным",Service);
    createButton(ExportLog,L"Сохранить журнал",Journal);createButton(CopyLog,L"Копировать журнал",Journal);
    logList=CreateWindowExW(WS_EX_CLIENTEDGE,WC_LISTVIEWW,L"События сервера",WS_CHILD|WS_VISIBLE|WS_TABSTOP|LVS_REPORT|LVS_SHOWSELALWAYS,0,0,1,1,content,nullptr,instance,nullptr);
    ListView_SetExtendedListViewStyle(logList,LVS_EX_FULLROWSELECT|LVS_EX_DOUBLEBUFFER|LVS_EX_LABELTIP);
    ListView_SetBkColor(logList,White);ListView_SetTextBkColor(logList,White);ListView_SetTextColor(logList,Text);
    const wchar_t* cols[]={L"Время",L"Уровень",L"Событие"};for(int i=0;i<3;++i){LVCOLUMNW col={};col.mask=LVCF_TEXT|LVCF_WIDTH;col.cx=px(i?100:80);col.pszText=const_cast<wchar_t*>(cols[i]);ListView_InsertColumn(logList,i,&col);}
    refreshFonts();
    SendMessageW(control(User),EM_SETCUEBANNER,TRUE,reinterpret_cast<LPARAM>(L"Например: proxyuser"));
    SendMessageW(control(Password),EM_SETCUEBANNER,TRUE,reinterpret_cast<LPARAM>(L"Не менее 8 символов"));
    SendMessageW(control(AllowIp),EM_SETCUEBANNER,TRUE,reinterpret_cast<LPARAM>(L"Любой IP с авторизацией"));
    SendMessageW(control(UpstreamHost),EM_SETCUEBANNER,TRUE,reinterpret_cast<LPARAM>(L"IP или домен внешнего прокси"));
    SendMessageW(control(DnsServer),EM_SETCUEBANNER,TRUE,reinterpret_cast<LPARAM>(L"Пусто — системный DNS"));
    SendMessageW(control(MtPublicHost),EM_SETCUEBANNER,TRUE,reinterpret_cast<LPARAM>(L"Публичный IP VDS или ваш домен"));
}

std::wstring ini(const wchar_t* key,const wchar_t* fallback=L"") { wchar_t b[8192]={};GetPrivateProfileStringW(L"proxy",key,fallback,b,8192,iniPath.c_str());return b; }
bool readUnsigned(const std::wstring& s,unsigned maximum,unsigned& out) { if(s.empty()||s.size()>10)return false;out=0;for(wchar_t c:s){if(c<L'0'||c>L'9')return false;unsigned d=c-L'0';if(out>maximum/10||(out==maximum/10&&d>maximum%10))return false;out=out*10+d;}return true; }
int hex(wchar_t c) { if(c>=L'0'&&c<=L'9')return c-L'0';if(c>=L'A'&&c<=L'F')return c-L'A'+10;if(c>=L'a'&&c<=L'f')return c-L'a'+10;return -1; }
std::wstring encodeUsername(const std::string& value) {
    // INI APIs remove matching surrounding quotes; hex preserves every accepted username exactly.
    const wchar_t* digits=L"0123456789ABCDEF";std::wstring out;out.reserve(value.size()*2);
    for(unsigned char c:value){out+=digits[c>>4];out+=digits[c&15];}return out;
}
bool loadUsername(const wchar_t* encodedKey,const wchar_t* legacyKey,std::wstring& value) {
    value.clear();std::wstring encoded=ini(encodedKey,L"#missing#");
    if(encoded==L"#missing#"){value=ini(legacyKey);return true;}
    if(encoded.size()%2||encoded.size()>2048)return false;
    std::string raw;raw.reserve(encoded.size()/2);
    for(std::size_t i=0;i<encoded.size();i+=2){int a=hex(encoded[i]),b=hex(encoded[i+1]);if(a<0||b<0)return false;raw+=static_cast<char>(a*16+b);}
    if(raw.empty())return true;
    if(raw.find('\0')!=std::string::npos||raw.find('\r')!=std::string::npos||raw.find('\n')!=std::string::npos)return false;
    int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,raw.data(),static_cast<int>(raw.size()),nullptr,0);
    if(!n)return false;
    value.resize(n);MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,raw.data(),static_cast<int>(raw.size()),&value[0],n);return true;
}
bool encrypt(const std::string& password,std::wstring& encoded,DWORD& error) {
    DATA_BLOB input={static_cast<DWORD>(password.size()),reinterpret_cast<BYTE*>(const_cast<char*>(password.data()))},output={};
    if(!CryptProtectData(&input,L"Proxy Server password",nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&output)){error=GetLastError();return false;}
    const wchar_t* digits=L"0123456789ABCDEF";encoded.clear();encoded.reserve(output.cbData*2);for(DWORD i=0;i<output.cbData;++i){encoded+=digits[output.pbData[i]>>4];encoded+=digits[output.pbData[i]&15];}LocalFree(output.pbData);return true;
}
bool decrypt(const std::wstring& encoded,std::string& password) {
    if(encoded.empty()||encoded.size()%2||encoded.size()>8190)return false;
    std::vector<BYTE> raw;raw.reserve(encoded.size()/2);for(std::size_t i=0;i<encoded.size();i+=2){int a=hex(encoded[i]),b=hex(encoded[i+1]);if(a<0||b<0)return false;raw.push_back(static_cast<BYTE>(a*16+b));}
    DATA_BLOB input={static_cast<DWORD>(raw.size()),raw.data()},output={};if(!CryptUnprotectData(&input,nullptr,nullptr,nullptr,nullptr,CRYPTPROTECT_UI_FORBIDDEN,&output))return false;
    password.assign(reinterpret_cast<const char*>(output.pbData),output.cbData);SecureZeroMemory(output.pbData,output.cbData);LocalFree(output.pbData);return true;
}
std::wstring startupCommand() { return L"\""+exePath+L"\" --minimized"; }
bool startupEnabled() {
    HKEY key=nullptr;if(RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_QUERY_VALUE,&key)!=ERROR_SUCCESS)return false;
    wchar_t b[32768]={};DWORD type=0,n=sizeof(b);LONG result=RegQueryValueExW(key,RunValue,nullptr,&type,reinterpret_cast<BYTE*>(b),&n);RegCloseKey(key);
    b[32767]=L'\0';
    return result==ERROR_SUCCESS&&type==REG_SZ&&n>=sizeof(wchar_t)&&n<=sizeof(b)&&_wcsicmp(b,startupCommand().c_str())==0;
}
bool setStartup(bool on,std::wstring& error) {
    if(!on&&!startupEnabled())return true; // Never delete another installation's startup registration.
    HKEY key=nullptr;LONG r=RegCreateKeyExW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,nullptr,0,KEY_SET_VALUE,nullptr,&key,nullptr);
    if(r==ERROR_SUCCESS){if(on){std::wstring command=startupCommand();r=RegSetValueExW(key,RunValue,0,REG_SZ,reinterpret_cast<const BYTE*>(command.c_str()),static_cast<DWORD>((command.size()+1)*sizeof(wchar_t)));}else{r=RegDeleteValueW(key,RunValue);if(r==ERROR_FILE_NOT_FOUND)r=ERROR_SUCCESS;}RegCloseKey(key);}
    if(r!=ERROR_SUCCESS){error=L"Не удалось изменить запуск при входе в Windows. "+systemError(r);return false;}return true;
}
bool disableLegacyWindowStartup(std::wstring& error) {
    HKEY key=nullptr;LONG result=RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",0,KEY_QUERY_VALUE|KEY_SET_VALUE,&key);
    if(result==ERROR_FILE_NOT_FOUND)return true;
    if(result!=ERROR_SUCCESS){error=L"Не удалось отключить автозапуск старого окна: "+systemError(result);return false;}
    wchar_t value[32768]={};DWORD type=0,bytes=sizeof(value);result=RegQueryValueExW(key,RunValue,nullptr,&type,reinterpret_cast<BYTE*>(value),&bytes);
    if(result==ERROR_FILE_NOT_FOUND){RegCloseKey(key);return true;}
    if(result!=ERROR_SUCCESS||type!=REG_SZ||bytes>sizeof(value)){RegCloseKey(key);error=L"Запись автозапуска PrivateProxyServer имеет неизвестный формат. Отключите её в автозагрузке Windows вручную.";return false;}
    value[32767]=L'\0';int count=0;LPWSTR* args=CommandLineToArgvW(value,&count);bool owned=false;
    if(args&&count==2&&_wcsicmp(args[1],L"--minimized")==0){std::wstring path=args[0];std::size_t slash=path.find_last_of(L"\\/");std::wstring filename=slash==std::wstring::npos?path:path.substr(slash+1);owned=_wcsicmp(filename.c_str(),L"ProxyServer.exe")==0;}
    if(args)LocalFree(args);
    if(!owned){RegCloseKey(key);error=L"Запись PrivateProxyServer отличается от штатного автозапуска старого окна. Она оставлена без изменений; проверьте автозагрузку Windows.";return false;}
    result=RegDeleteValueW(key,RunValue);RegCloseKey(key);
    if(result!=ERROR_SUCCESS){error=L"Не удалось отключить автозапуск старого окна: "+systemError(result);return false;}return true;
}
bool fields(proxy::Config& c,std::wstring& error,bool allowUnconfigured=false) {
    fieldErrorPage=Settings;
    c.user=ascii(getText(control(User)));c.password=ascii(getText(control(Password)));c.allowIp=ascii(getText(control(AllowIp)));c.bindAddress=ascii(getText(control(BindAddress)));
    c.enableSocks=checked(EnableSocks);c.enableHttp=checked(EnableHttp);c.enableChainSocks=checked(EnableChainSocks);c.enableChainHttp=checked(EnableChainHttp);
    c.enableSocksUdp=checked(SocksUdp);
    unsigned udpMin=0,udpMax=0;if(c.enableSocksUdp&&(!readUnsigned(getText(control(UdpPortMin)),65535,udpMin)||!readUnsigned(getText(control(UdpPortMax)),65535,udpMax)||!udpMin||!udpMax||udpMin>udpMax)){fieldErrorPage=TlsDns;error=configError("UDP_RANGE");return false;}
    c.udpPortMin=c.enableSocksUdp?static_cast<unsigned short>(udpMin):configured.udpPortMin;c.udpPortMax=c.enableSocksUdp?static_cast<unsigned short>(udpMax):configured.udpPortMax;c.enableHttps=checked(EnableHttps);c.enableSocksTls=checked(EnableSocksTls);c.enableDns=checked(EnableDns);c.tlsUseChain=checked(TlsUseChain);
    c.tlsCertFile=utf8(getText(control(TlsCert)));c.tlsKeyFile=utf8(getText(control(TlsKey)));c.dnsServer=utf8(getText(control(DnsServer)));
    const bool chain=c.enableChainSocks||c.enableChainHttp||((c.enableHttps||c.enableSocksTls)&&c.tlsUseChain);
    c.upstreamType=SendMessageW(control(UpstreamType),CB_GETCURSEL,0,0)==1?"http":"socks5";
    // Disabled upstream settings can be incomplete; retain their text until the chain is enabled.
    c.upstreamHost=utf8(getText(control(UpstreamHost)));c.upstreamUser=utf8(getText(control(UpstreamUser)));c.upstreamPassword=utf8(getText(control(UpstreamPassword)));
    auto portField=[&](int id,bool enabled,unsigned short fallback,unsigned short& target,Page page)->bool {
        unsigned p=0;if(readUnsigned(getText(control(id)),65535,p)&&p){target=static_cast<unsigned short>(p);return true;}
        if(!enabled){target=fallback;return true;}
        fieldErrorPage=page;error=configError(id==UpstreamPort?"UPSTREAM":"PORTS");return false;
    };
    if(!portField(SocksPort,c.enableSocks,configured.socksPort,c.socksPort,Settings)||
       !portField(HttpPort,c.enableHttp,configured.httpPort,c.httpPort,Settings)||
       !portField(ChainSocksPort,c.enableChainSocks,configured.chainSocksPort,c.chainSocksPort,Chain)||
       !portField(ChainHttpPort,c.enableChainHttp,configured.chainHttpPort,c.chainHttpPort,Chain)||
       !portField(UpstreamPort,chain,configured.upstreamPort,c.upstreamPort,Chain)||
       !portField(HttpsPort,c.enableHttps,configured.httpsPort,c.httpsPort,TlsDns)||
       !portField(SocksTlsPort,c.enableSocksTls,configured.socksTlsPort,c.socksTlsPort,TlsDns)||
       !portField(DnsPort,c.enableDns,configured.dnsPort,c.dnsPort,TlsDns))return false;
    if(!readUnsigned(getText(control(MaxConnections)),10000,c.maxConnections)){error=configError("LIMIT");return false;}
    if(!readUnsigned(getText(control(ConnectTimeout)),300,c.connectTimeoutSeconds)){error=configError("TIMEOUT_CONNECT");return false;}
    if(!readUnsigned(getText(control(IdleTimeout)),86400,c.idleTimeoutSeconds)){error=configError("TIMEOUT_HTTP");return false;}
    if(allowUnconfigured&&c.user.empty()&&c.password.empty())return true;
    std::string reason;
    if(!proxy::validate(c,reason)) {
        if(reason.find("UPSTREAM")==0)fieldErrorPage=Chain;
        if(reason=="TLS"||reason=="DNS"||reason.find("TLS_")==0||reason.find("DNS_")==0||reason.find("UDP_")==0)fieldErrorPage=TlsDns;
        if(reason=="PORTS") {
            const bool enabled[]={c.enableSocks,c.enableHttp,c.enableChainSocks,c.enableChainHttp,c.enableHttps,c.enableSocksTls,c.enableDns};
            const unsigned values[]={c.socksPort,c.httpPort,c.chainSocksPort,c.chainHttpPort,c.httpsPort,c.socksTlsPort,c.dnsPort};
            const Page pages[]={Settings,Settings,Chain,Chain,TlsDns,TlsDns,TlsDns};
            std::vector<unsigned> used;
            for(unsigned i=0;i<7;++i)if(enabled[i]){if(!values[i]||std::find(used.begin(),used.end(),values[i])!=used.end()){fieldErrorPage=pages[i];break;}used.push_back(values[i]);}
        }
        error=configError(reason);return false;
    }
    return true;
}

bool atomicWrite(const std::wstring& path,const char* data,DWORD size,std::wstring& error) {
    std::wstring temp=path+L".tmp";HANDLE h=CreateFileW(temp.c_str(),GENERIC_WRITE,0,nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(h==INVALID_HANDLE_VALUE){error=L"Не удалось создать файл. "+systemError(GetLastError());return false;}
    DWORD written=0;bool ok=WriteFile(h,data,size,&written,nullptr)&&written==size&&FlushFileBuffers(h);DWORD code=ok?ERROR_SUCCESS:GetLastError();CloseHandle(h);
    if(ok&&!MoveFileExW(temp.c_str(),path.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)){ok=false;code=GetLastError();}
    if(!ok){DeleteFileW(temp.c_str());error=L"Не удалось сохранить файл. "+systemError(code);}return ok;
}
std::wstring mtIni(const wchar_t* key,const wchar_t* fallback=L"") {
    wchar_t b[8192]={};GetPrivateProfileStringW(L"mtproto",key,fallback,b,8192,iniPath.c_str());return b;
}
bool serializeMtSection(const mtproto::Config& c,const std::wstring& domain,bool automatic,std::wstring& body,std::wstring& error) {
    DWORD code=0;std::wstring encrypted;
    if(!c.secret.empty()&&!encrypt(c.secret,encrypted,code)){error=L"Не удалось защитить секрет MTProto. "+systemError(code);return false;}
    body=L"\r\n[mtproto]\r\nbind_address="+wide(c.bindAddress)+L"\r\nport="+std::to_wstring(c.listenPort)+
      L"\r\npublic_host="+wide(c.publicHost)+L"\r\ntls_domain="+domain+L"\r\nsecret_dpapi="+encrypted+
      L"\r\nautostart="+(automatic?L"1":L"0")+L"\r\n";
    return true;
}
bool existingSection(const wchar_t* section,std::wstring& body,bool prefix,std::wstring& error) {
    std::vector<wchar_t> raw(32768);DWORD n=GetPrivateProfileSectionW(section,raw.data(),static_cast<DWORD>(raw.size()),iniPath.c_str());
    if(n>=raw.size()-2){error=L"Раздел настроек proxy.ini слишком велик; файл оставлен без изменений.";return false;}
    if(!prefix&&n==0){body.clear();return true;}
    body=(prefix?L"\xFEFF[":L"\r\n[")+std::wstring(section)+L"]\r\n";
    for(std::size_t pos=0;pos<n;){std::wstring row(raw.data()+pos);body+=row+L"\r\n";pos+=row.size()+1;}
    return true;
}
bool existingProxySection(std::wstring& body,std::wstring& error) { return existingSection(L"proxy",body,true,error); }

bool saveConfig(const proxy::Config& c,std::wstring& error) {
    DWORD e=0;std::wstring encoded,upstreamEncoded;
    if(!c.upstreamPassword.empty()&&!encrypt(c.upstreamPassword,upstreamEncoded,e)){error=L"Не удалось защитить пароль внешнего прокси. "+systemError(e);return false;}
    if(!encrypt(c.password,encoded,e)){error=L"Не удалось защитить пароль средствами Windows. "+systemError(e);return false;}
    std::wstring body=L"\xFEFF[proxy]\r\nversion=2\r\nuser_utf8_hex="+encodeUsername(c.user)+L"\r\npassword_dpapi="+encoded+
      L"\r\nsocks_port="+std::to_wstring(c.socksPort)+L"\r\nhttp_port="+std::to_wstring(c.httpPort)+
      L"\r\ntls_cert_name="+getText(control(TlsCertHost))+L"\r\nudp_port_min="+std::to_wstring(c.udpPortMin)+L"\r\nudp_port_max="+std::to_wstring(c.udpPortMax)+
      L"\r\nenable_socks_udp="+(c.enableSocksUdp?L"1":L"0")+L"\r\nenable_https="+(c.enableHttps?L"1":L"0")+L"\r\nhttps_port="+std::to_wstring(c.httpsPort)+
      L"\r\nenable_socks_tls="+(c.enableSocksTls?L"1":L"0")+L"\r\nsocks_tls_port="+std::to_wstring(c.socksTlsPort)+L"\r\ntls_cert_file="+wide(c.tlsCertFile)+L"\r\ntls_key_file="+wide(c.tlsKeyFile)+
      L"\r\ntls_use_chain="+(c.tlsUseChain?L"1":L"0")+L"\r\ndns_server="+wide(c.dnsServer)+L"\r\nenable_dns="+(c.enableDns?L"1":L"0")+L"\r\ndns_port="+std::to_wstring(c.dnsPort)+
      L"\r\nenable_socks="+(c.enableSocks?L"1":L"0")+L"\r\nenable_http="+(c.enableHttp?L"1":L"0")+
      L"\r\nenable_chain_socks="+(c.enableChainSocks?L"1":L"0")+L"\r\nenable_chain_http="+(c.enableChainHttp?L"1":L"0")+
      L"\r\nchain_socks_port="+std::to_wstring(c.chainSocksPort)+L"\r\nchain_http_port="+std::to_wstring(c.chainHttpPort)+
      L"\r\nupstream_type="+wide(c.upstreamType)+L"\r\nupstream_host="+wide(c.upstreamHost)+L"\r\nupstream_port="+std::to_wstring(c.upstreamPort)+
      L"\r\nupstream_user_utf8_hex="+encodeUsername(c.upstreamUser)+L"\r\nupstream_password_dpapi="+upstreamEncoded+
      L"\r\nbind_address="+wide(c.bindAddress)+L"\r\nallow_ip="+wide(c.allowIp)+L"\r\nmax_connections="+std::to_wstring(c.maxConnections)+
      L"\r\nconnect_timeout="+std::to_wstring(c.connectTimeoutSeconds)+L"\r\nidle_timeout="+std::to_wstring(c.idleTimeoutSeconds)+
      L"\r\nautostart="+(checked(AutoProxy)?L"1":L"0")+L"\r\nclose_to_tray="+(checked(CloseTray)?L"1":L"0")+L"\r\n";
    std::wstring mtSection;if(!existingSection(L"mtproto",mtSection,false,error))return false;body+=mtSection;
    // Complete the new encrypted config before replacing the previous file.
    if(!atomicWrite(iniPath,reinterpret_cast<const char*>(body.data()),static_cast<DWORD>(body.size()*sizeof(wchar_t)),error)){error+=L"\n\nРаспакуйте программу в папку с правом записи, например C:\\ProxyServer.";return false;}
    WritePrivateProfileStringW(nullptr,nullptr,nullptr,iniPath.c_str());
    if(!setStartup(checked(AutoWindows),error)){error=L"Параметры прокси сохранены. "+error;return false;}
    return true;
}
void appendDiskLog(const JournalRow& row) {
    std::wstring folder=appDir+L"logs";CreateDirectoryW(folder.c_str(),nullptr);
    WIN32_FILE_ATTRIBUTE_DATA attr={};if(GetFileAttributesExW(logPath.c_str(),GetFileExInfoStandard,&attr)&&(attr.nFileSizeHigh||attr.nFileSizeLow>1024*1024)) {
        std::wstring backup=logPath+L".1";MoveFileExW(logPath.c_str(),backup.c_str(),MOVEFILE_REPLACE_EXISTING);
    }
    HANDLE h=CreateFileW(logPath.c_str(),FILE_APPEND_DATA,FILE_SHARE_READ,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(h==INVALID_HANDLE_VALUE){logWriteFailed=true;return;}
    SYSTEMTIME t={};GetLocalTime(&t);wchar_t date[24]={};swprintf(date,24,L"%04u-%02u-%02u ",t.wYear,t.wMonth,t.wDay);
    std::string line=utf8(std::wstring(date)+row.time+L" ["+row.level+L"] "+row.message+L"\r\n");DWORD written=0;
    if(!WriteFile(h,line.data(),static_cast<DWORD>(line.size()),&written,nullptr)||written!=line.size())logWriteFailed=true;
    CloseHandle(h);
}
void addJournal(const std::wstring& level,const std::wstring& message,const std::wstring& time=L"") {
    JournalRow row={time.empty()?clockText():time,level,message};journalRows.push_back(row);if(journalRows.size()>400){journalRows.pop_front();ListView_DeleteItem(logList,0);}
    int index=ListView_GetItemCount(logList);LVITEMW item={};item.mask=LVIF_TEXT;item.iItem=index;item.pszText=const_cast<wchar_t*>(row.time.c_str());ListView_InsertItem(logList,&item);
    ListView_SetItemText(logList,index,1,const_cast<wchar_t*>(row.level.c_str()));ListView_SetItemText(logList,index,2,const_cast<wchar_t*>(row.message.c_str()));
    if(currentPage==Journal)ListView_EnsureVisible(logList,index,FALSE);
    appendDiskLog(row);
}
void collectCoreEvents() {
    for(const auto& event:server.events(lastCoreEvent)) {
        lastCoreEvent=(std::max)(lastCoreEvent,event.id);std::wstring level=event.level=="error"?L"Ошибка":event.level=="warning"?L"Внимание":L"Инфо";
        addJournal(level,wide(event.message),wide(event.time));
    }
}
bool loadConfig() {
    loading=true;
    bool exists=GetFileAttributesW(iniPath.c_str())!=INVALID_FILE_ATTRIBUTES;
    std::wstring loadedUser,loadedUpstreamUser;
    bool userDecoded=loadUsername(L"user_utf8_hex",L"user",loadedUser);
    bool upstreamUserDecoded=loadUsername(L"upstream_user_utf8_hex",L"upstream_user",loadedUpstreamUser);
    setText(User,loadedUser);setText(SocksPort,ini(L"socks_port",ini(L"port",L"1080").c_str()));setText(HttpPort,ini(L"http_port",L"8080"));
    setText(BindAddress,ini(L"bind_address",L"0.0.0.0"));setText(AllowIp,ini(L"allow_ip"));
    setText(MaxConnections,ini(L"max_connections",L"256"));setText(ConnectTimeout,ini(L"connect_timeout",L"15"));setText(IdleTimeout,ini(L"idle_timeout",L"1800"));
    setText(TlsCertHost,ini(L"tls_cert_name"));setText(UdpPortMin,ini(L"udp_port_min",L"20000"));setText(UdpPortMax,ini(L"udp_port_max",L"20100"));
    check(SocksUdp,ini(L"enable_socks_udp",L"1")==L"1");check(EnableHttps,ini(L"enable_https",L"0")==L"1");check(EnableSocksTls,ini(L"enable_socks_tls",L"0")==L"1");check(EnableDns,ini(L"enable_dns",L"0")==L"1");check(TlsUseChain,ini(L"tls_use_chain",L"0")==L"1");
    setText(HttpsPort,ini(L"https_port",L"8443"));setText(SocksTlsPort,ini(L"socks_tls_port",L"1443"));setText(DnsPort,ini(L"dns_port",L"1053"));setText(TlsCert,ini(L"tls_cert_file"));setText(TlsKey,ini(L"tls_key_file"));setText(DnsServer,ini(L"dns_server"));
    check(EnableSocks,ini(L"enable_socks",L"1")==L"1");check(EnableHttp,ini(L"enable_http",L"1")==L"1");
    check(EnableChainSocks,ini(L"enable_chain_socks",L"0")==L"1");check(EnableChainHttp,ini(L"enable_chain_http",L"0")==L"1");
    setText(ChainSocksPort,ini(L"chain_socks_port",L"1081"));setText(ChainHttpPort,ini(L"chain_http_port",L"8081"));setText(UpstreamHost,ini(L"upstream_host"));
    setText(UpstreamPort,ini(L"upstream_port",L"1080"));setText(UpstreamUser,loadedUpstreamUser);SendMessageW(control(UpstreamType),CB_SETCURSEL,ini(L"upstream_type",L"socks5")==L"http"?1:0,0);
    check(AutoProxy,ini(L"autostart",L"0")==L"1");check(AutoWindows,startupEnabled());closeToTray=ini(L"close_to_tray",L"1")==L"1";check(CloseTray,closeToTray);
    std::wstring encoded=ini(L"password_dpapi");std::string password;bool decoded=decrypt(encoded,password);
    if(decoded){setText(Password,wide(password));clearString(password);}
    std::wstring upstreamEncoded=ini(L"upstream_password_dpapi");std::string upstreamPassword;bool upstreamDecoded=upstreamEncoded.empty()||decrypt(upstreamEncoded,upstreamPassword);
    if(upstreamDecoded){setText(UpstreamPassword,wide(upstreamPassword));clearString(upstreamPassword);}
    loading=false;dirty=false;
    if(!exists){setBanner(L"Задайте логин и пароль, затем нажмите «Сохранить и запустить».");return false;}
    if(!userDecoded||!upstreamUserDecoded){fieldErrorPage=userDecoded?Chain:Settings;setBanner(L"Сохранённый логин повреждён. Введите его заново; автоматический запуск отменён.",true);addJournal(L"Внимание",L"Не удалось прочитать сохранённый логин; автоматический запуск отменён.");return false;}
    if(!upstreamDecoded){fieldErrorPage=Chain;setBanner(L"Windows не смогла прочитать пароль внешнего прокси. Введите его заново на вкладке «Цепочка».",true);addJournal(L"Внимание",L"Пароль внешнего прокси не расшифрован; автоматический запуск отменён.");return false;}
    if(loadedUser.empty()&&encoded.empty()){setBanner(L"SOCKS5 / HTTP пока не настроены. Для их запуска задайте учётную запись.");return false;}
    if(!encoded.empty()&&!decoded){setBanner(L"Windows не смогла прочитать сохранённый пароль. Введите его заново под текущей учётной записью.",true);addJournal(L"Внимание",L"Сохранённый пароль не расшифрован; автоматический запуск отменён.");return false;}
    std::wstring error;proxy::Config c;
    if(!fields(c,error)){setBanner(L"Проверьте настройки: "+error,true);clearString(c.password);clearString(c.upstreamPassword);return false;}
    configured=c;clearString(configured.password);clearString(configured.upstreamPassword);clearString(c.password);clearString(c.upstreamPassword);setBanner(L"Настройки загружены.");return checked(AutoProxy);
}
std::wstring mtError(const std::string& error) {
    if(error=="MT_PORT")return L"Укажите TCP-порт MTProto от 1 до 65535.";
    if(error=="MT_BIND")return L"Укажите IPv4-адрес интерфейса или 0.0.0.0 для всех интерфейсов.";
    if(error=="MT_SECRET")return L"Создайте корректный секрет MTProto для выбранного домена FakeTLS.";
    if(error=="MT_DOMAIN")return L"Укажите доменное имя сайта для FakeTLS, без https://, порта и пути.";
    if(error=="MT_PUBLIC_HOST")return L"Укажите внешний IP или домен VDS, без протокола и пути.";
    return wide(error);
}
void setMtBanner(const std::wstring& value,bool error=false) { mtBanner=value;mtBannerError=error;InvalidateRect(content,nullptr,FALSE); }
bool secretDomainText(const std::string& secret,std::wstring& domain) {
    std::string decoded;if(!mtproto::secretDomain(secret,decoded))return false;domain=wide(decoded);return true;
}

bool mtFields(mtproto::Config& c,std::wstring& domain,std::wstring& error) {
    unsigned port=0;if(!readUnsigned(getText(control(MtPort)),65535,port)||port==0){error=L"Порт MTProto должен быть числом от 1 до 65535.";return false;}
    c.listenPort=static_cast<unsigned short>(port);c.bindAddress=ascii(getText(control(MtBind)));c.publicHost=ascii(getText(control(MtPublicHost)));c.secret=ascii(getText(control(MtSecret)));domain=getText(control(MtDomain));
    std::string reason;if(!mtproto::validate(c,reason)){error=mtError(reason);return false;}
    std::wstring actualDomain;
    if(!secretDomainText(c.secret,actualDomain)){error=L"Неверный формат секрета MTProto. Нажмите «Создать секрет».";return false;}
    if(_wcsicmp(actualDomain.c_str(),domain.c_str())!=0){error=L"Домен FakeTLS изменён. Создайте новый секрет для этого домена или верните домен из существующего секрета: "+actualDomain;return false;}
    if(proxyRunning()) {
        bool occupied=(configured.enableSocks&&c.listenPort==configured.socksPort)||(configured.enableHttp&&c.listenPort==configured.httpPort)||
          (configured.enableChainSocks&&c.listenPort==configured.chainSocksPort)||(configured.enableChainHttp&&c.listenPort==configured.chainHttpPort)||
          (configured.enableHttps&&c.listenPort==configured.httpsPort)||(configured.enableSocksTls&&c.listenPort==configured.socksTlsPort)||(configured.enableDns&&c.listenPort==configured.dnsPort);
        if(occupied){error=L"Этот порт уже используется обычным прокси. Выберите отдельный порт MTProto.";return false;}
    }
    return true;
}
bool saveMtFields(mtproto::Config& c,bool startInService=false) {
    if(!canUseBackend())return false;
    std::wstring domain,error;if(!mtFields(c,domain,error)){setMtBanner(error,true);alert(error,MB_ICONWARNING);return false;}
    if(serviceMode()) {
        ServiceRequest request;request.action=startInService?ServiceAction::SaveTelegramStart:ServiceAction::SaveTelegram;
        request.profile.mt=c;request.profile.mtAutoStart=checked(MtAuto);request.profile.tlsDomain=utf8(domain);queueServiceRequest(std::move(request));return false;
    }
    std::wstring body,section;if(!existingProxySection(body,error)||!serializeMtSection(c,domain,checked(MtAuto),section,error)){setMtBanner(error,true);alert(error);return false;}body+=section;
    if(!atomicWrite(iniPath,reinterpret_cast<const char*>(body.data()),static_cast<DWORD>(body.size()*sizeof(wchar_t)),error)){setMtBanner(error,true);alert(error);return false;}
    WritePrivateProfileStringW(nullptr,nullptr,nullptr,iniPath.c_str());clearString(mtConfigured.secret);mtConfigured=c;mtDomain=domain;mtAutostart=checked(MtAuto);mtDirty=false;
    setMtBanner(L"Настройки MTProto сохранены.");addJournal(L"Инфо",L"Параметры MTProto сохранены; секрет не записывается в журнал.");return true;
}
void updateMtState() {
    const bool on=telegramRunning(),available=canUseBackend();int locked[]={MtBind,MtPort,MtPublicHost,MtDomain,MtSecret,MtGenerate,MtAuto,MtSave};
    for(int id:locked)EnableWindow(control(id),available&&!on);
    SetWindowTextW(control(MtToggle),engineStateUnknown()?L"Нет связи":on?L"Остановить":L"Запустить");EnableWindow(control(MtToggle),available);
    EnableWindow(control(MtCopyLink),(!serviceMode()||serviceProfileLoaded)&&!serviceMutationBusy()&&GetWindowTextLengthW(control(MtSecret))>0&&GetWindowTextLengthW(control(MtPublicHost))>0);
}
bool loadMtConfig() {
    loading=true;setText(MtBind,mtIni(L"bind_address",L"0.0.0.0"));setText(MtPort,mtIni(L"port",L"443"));setText(MtPublicHost,mtIni(L"public_host"));setText(MtDomain,mtIni(L"tls_domain",L"www.microsoft.com"));check(MtAuto,mtIni(L"autostart",L"0")==L"1");
    std::wstring encrypted=mtIni(L"secret_dpapi");std::string secret;bool decoded=encrypted.empty()||decrypt(encrypted,secret);if(decoded)setText(MtSecret,wide(secret));clearString(secret);loading=false;mtDirty=false;
    if(!decoded){setMtBanner(L"Windows не смогла прочитать секрет MTProto. Введите его заново или создайте новый секрет.",true);addJournal(L"Внимание",L"Секрет MTProto не расшифрован; автоматический запуск отменён.");updateMtState();return false;}
    if(encrypted.empty()){setMtBanner(L"Укажите адрес VDS и создайте секрет, затем запустите MTProto.");updateMtState();return false;}
    mtproto::Config c;std::wstring domain,error;if(!mtFields(c,domain,error)){setMtBanner(error,true);clearString(c.secret);updateMtState();return false;}
    mtConfigured=c;clearString(c.secret);mtDomain=domain;mtAutostart=checked(MtAuto);setMtBanner(L"Настройки MTProto загружены.");updateMtState();return mtAutostart;
}
void refreshServiceDefaults() {
    if(serviceMode()||serviceOptionsDirty)return;
    proxy::Config proxyCandidate;std::wstring error;bool proxyValid=fields(proxyCandidate,error);
    check(ServiceProxyAuto,server.running()||proxyValid);clearString(proxyCandidate.password);clearString(proxyCandidate.upstreamPassword);
    mtproto::Config mtCandidate;std::wstring domain;bool mtValid=!getText(control(MtSecret)).empty()&&mtFields(mtCandidate,domain,error);
    check(ServiceMtAuto,mtController.running()||mtValid);clearString(mtCandidate.secret);
}
void applyProxyProfile(const service_host::Profile& profile) {
    const proxy::Config& c=profile.proxy;loading=true;
    setText(User,wide(c.user));setText(Password,wide(c.password));setText(AllowIp,wide(c.allowIp));setText(BindAddress,wide(c.bindAddress));
    check(EnableSocks,c.enableSocks);check(EnableHttp,c.enableHttp);setText(SocksPort,number(c.socksPort));setText(HttpPort,number(c.httpPort));
    check(EnableChainSocks,c.enableChainSocks);check(EnableChainHttp,c.enableChainHttp);setText(ChainSocksPort,number(c.chainSocksPort));setText(ChainHttpPort,number(c.chainHttpPort));
    setText(UpstreamHost,wide(c.upstreamHost));setText(UpstreamPort,number(c.upstreamPort));setText(UpstreamUser,wide(c.upstreamUser));setText(UpstreamPassword,wide(c.upstreamPassword));
    SendMessageW(control(UpstreamType),CB_SETCURSEL,c.upstreamType=="http"?1:0,0);
    check(EnableHttps,c.enableHttps);check(EnableSocksTls,c.enableSocksTls);setText(HttpsPort,number(c.httpsPort));setText(SocksTlsPort,number(c.socksTlsPort));
    setText(TlsCert,wide(c.tlsCertFile));setText(TlsKey,wide(c.tlsKeyFile));check(TlsUseChain,c.tlsUseChain);
    setText(DnsServer,wide(c.dnsServer));check(EnableDns,c.enableDns);setText(DnsPort,number(c.dnsPort));check(SocksUdp,c.enableSocksUdp);setText(UdpPortMin,number(c.udpPortMin));setText(UdpPortMax,number(c.udpPortMax));
    setText(MaxConnections,number(c.maxConnections));setText(ConnectTimeout,number(c.connectTimeoutSeconds));setText(IdleTimeout,number(c.idleTimeoutSeconds));
    check(AutoProxy,profile.proxyAutoStart);check(ServiceProxyAuto,profile.proxyAutoStart);
    configured=c;clearString(configured.password);clearString(configured.upstreamPassword);loading=false;dirty=false;
}
void applyTelegramProfile(const service_host::Profile& profile) {
    loading=true;clearString(mtConfigured.secret);mtConfigured=profile.mt;mtAutostart=profile.mtAutoStart;mtDomain=wide(profile.tlsDomain);
    setText(MtBind,wide(profile.mt.bindAddress));setText(MtPort,number(profile.mt.listenPort));setText(MtPublicHost,wide(profile.mt.publicHost));setText(MtSecret,wide(profile.mt.secret));
    if(mtDomain.empty()&&!profile.mt.secret.empty())secretDomainText(profile.mt.secret,mtDomain);
    if(mtDomain.empty())mtDomain=L"www.microsoft.com";
    setText(MtDomain,mtDomain);check(MtAuto,profile.mtAutoStart);check(ServiceMtAuto,profile.mtAutoStart);loading=false;mtDirty=false;
}
bool saveGuiPreferences(std::wstring& error) {
    if(!WritePrivateProfileStringW(L"proxy",L"close_to_tray",checked(CloseTray)?L"1":L"0",iniPath.c_str())){error=L"Не удалось сохранить поведение окна. "+systemError(GetLastError());return false;}
    if(!WritePrivateProfileStringW(L"proxy",L"tls_cert_name",getText(control(TlsCertHost)).c_str(),iniPath.c_str())){error=L"Не удалось сохранить имя для нового сертификата. "+systemError(GetLastError());return false;}
    // Cache flush returns zero by design; the two actual writes above are checked.
    WritePrivateProfileStringW(nullptr,nullptr,nullptr,iniPath.c_str());
    closeToTray=checked(CloseTray);return true;
}
void refreshServiceControls() {
    const bool busy=serviceMutationBusy(),known=serviceChecked&&serviceStatusKnown;
    EnableWindow(control(ServiceInstall),known&&!serviceMode()&&!busy&&!certGenerating);
    EnableWindow(control(ServiceStart),known&&serviceMode()&&serviceState.scmState==SERVICE_STOPPED&&!busy);
    EnableWindow(control(ServiceStop),known&&serviceMode()&&serviceState.scmState!=SERVICE_STOPPED&&serviceState.scmState!=SERVICE_STOP_PENDING&&!busy);
    EnableWindow(control(ServiceRemove),known&&serviceMode()&&!busy);
    EnableWindow(control(ServiceRefresh),!busy);
    EnableWindow(control(ServiceOpenData),serviceMode()&&!serviceState.dataDir.empty());
    EnableWindow(control(ServiceProxyAuto),known&&!serviceMode()&&!busy);
    EnableWindow(control(ServiceMtAuto),known&&!serviceMode()&&!busy);
    EnableWindow(control(ServiceFirewall),known&&!serviceMode()&&!busy);
    SetWindowTextW(control(ServiceRefresh),serviceMode()?L"Обновить профиль":L"Повторить проверку");
    SetWindowTextW(control(OpenFolder),protectedApplicationFolder()?L"Скопировать путь":L"Папка программы");
    SetWindowTextW(control(AutoProxy),serviceMode()?L"Запускать прокси при загрузке Windows (служба)":L"Запускать прокси при открытии программы");
    SetWindowTextW(control(MtAuto),serviceMode()?L"Запускать MTProto при загрузке Windows (служба)":L"Запускать MTProto при открытии программы");
    SetWindowTextW(control(AutoWindows),L"Автозапуск окна требует UAC; используйте «Службу»");EnableWindow(control(AutoWindows),FALSE);
}
void recordStats(const proxy::Stats& stats) {
    latest=stats;ULONGLONG now=GetTickCount64();double elapsed=lastSample&&now>lastSample?(now-lastSample)/1000.0:0;
    uploadMbps=elapsed&&latest.metricsAvailable&&previous.metricsAvailable&&latest.sent>=previous.sent?(latest.sent-previous.sent)*8.0/(elapsed*1000000.0):0;
    downloadMbps=elapsed&&latest.metricsAvailable&&previous.metricsAvailable&&latest.received>=previous.received?(latest.received-previous.received)*8.0/(elapsed*1000000.0):0;
    if(!proxyRunning()){uploadMbps=0;downloadMbps=0;}
    if(latest.metricsAvailable){uploadHistory.push_back(uploadMbps);downloadHistory.push_back(downloadMbps);if(uploadHistory.size()>60)uploadHistory.pop_front();if(downloadHistory.size()>60)downloadHistory.pop_front();}
    else{uploadHistory.clear();downloadHistory.clear();}
    previous=latest;lastSample=now;
}
void runServiceRequest(ServiceRequest request) {
    ServiceReply reply;reply.request=request;
    bool reload=false;
    try {
        switch(request.action) {
          case ServiceAction::Discover:case ServiceAction::Poll:case ServiceAction::Reload:reply.ok=true;break;
          case ServiceAction::Install:reply.ok=service_host::install(request.profile,reply.error);break;
          case ServiceAction::ActivateInstalled:
            reply.ok=service_host::startService(reply.error);
            if(reply.ok) {
                std::string proxyError,telegramError;
                bool proxyOk=!request.restoreProxy||service_host::command(service_host::Command::StartProxy,proxyError);
                bool mtOk=!request.restoreMt||service_host::command(service_host::Command::StartTelegram,telegramError);
                reply.ok=proxyOk&&mtOk;
                if(!proxyOk)reply.error=u8"Прокси: "+proxyError;
                if(!mtOk)reply.error+=(reply.error.empty()?"":"\n")+std::string("MTProto: ")+telegramError;
            }
            reload=true;break;
          case ServiceAction::Start:reply.ok=service_host::startService(reply.error);break;
          case ServiceAction::Stop:reply.ok=service_host::stopService(reply.error);break;
          case ServiceAction::Remove:reply.ok=service_host::uninstall(reply.error);break;
          case ServiceAction::SaveProxy:case ServiceAction::SaveProxyStart:
            reply.ok=service_host::saveProxy(request.profile.proxy,request.profile.proxyAutoStart,reply.error);reload=reply.ok;
            if(reply.ok&&request.action==ServiceAction::SaveProxyStart)reply.ok=service_host::startService(reply.error)&&service_host::command(service_host::Command::StartProxy,reply.error);
            break;
          case ServiceAction::SaveTelegram:case ServiceAction::SaveTelegramStart:
            reply.ok=service_host::saveTelegram(request.profile.mt,request.profile.mtAutoStart,request.profile.tlsDomain,reply.error);reload=reply.ok;
            if(reply.ok&&request.action==ServiceAction::SaveTelegramStart)reply.ok=service_host::startService(reply.error)&&service_host::command(service_host::Command::StartTelegram,reply.error);
            break;
          case ServiceAction::StopProxy:reply.ok=service_host::command(service_host::Command::StopProxy,reply.error);break;
          case ServiceAction::StopTelegram:reply.ok=service_host::command(service_host::Command::StopTelegram,reply.error);break;
        }
        reply.stateOk=service_host::getState(reply.state,reply.stateError,request.afterEvent);
        if((request.action==ServiceAction::Discover||request.action==ServiceAction::Reload||reload)&&reply.state.installed) {
            std::string loadError;reply.profileLoaded=service_host::loadProfile(reply.profile,loadError);
            if(!reply.profileLoaded){reply.ok=false;if(reply.error.empty())reply.error=loadError;}
        }
        if(!reply.stateOk&&reply.error.empty()&&request.action!=ServiceAction::Poll)reply.error=reply.stateError;
    }catch(...) {reply.ok=false;reply.error=u8"Операция службы завершилась ошибкой: недостаточно ресурсов.";}
    clearProfile(request.profile);clearProfile(reply.request.profile);
    serviceReply=std::move(reply);serviceFinished.store(true,std::memory_order_release);PostMessageW(window,ServiceCompleteMessage,0,0);
}
void queueServiceRequest(ServiceRequest request) {
    request.afterEvent=lastServiceEvent;
    if(serviceWorkerActive) {
        if(request.action==ServiceAction::Poll){clearProfile(request.profile);return;}
        if(queuedServiceRequest){clearProfile(request.profile);return;}
        queuedServiceRequest.reset(new ServiceRequest(std::move(request)));refreshServiceControls();updateState();updateMtState();return;
    }
    activeServiceAction=request.action;serviceWorkerActive=true;serviceFinished.store(false,std::memory_order_relaxed);
    if(request.action!=ServiceAction::Poll){serviceBannerError=false;serviceBanner=L"Выполняется операция службы…";}
    try {serviceWorker=std::thread(runServiceRequest,std::move(request));}
    catch(...) {serviceWorkerActive=false;clearProfile(request.profile);serviceBanner=L"Не удалось создать рабочий поток службы.";serviceBannerError=true;}
    refreshServiceControls();updateState();updateMtState();InvalidateRect(content,nullptr,FALSE);
}
void consumeServiceReply() {
    if(!serviceWorkerActive||!serviceFinished.load(std::memory_order_acquire))return;
    if(serviceWorker.joinable())serviceWorker.join();
    serviceWorkerActive=false;
    ServiceReply reply=std::move(serviceReply);const ServiceAction action=reply.request.action;
    const bool wasInstalled=serviceInstalled,wasReachable=serviceState.reachable;
    const bool scmKnown=reply.stateOk||(reply.state.installed&&reply.state.scmState!=0);
    serviceChecked=true;serviceStatusKnown=scmKnown;
    if(scmKnown){serviceInstalled=reply.state.installed;serviceState=reply.state;}
    else{serviceState.reachable=false;serviceState.proxyRunning=false;serviceState.mtRunning=false;serviceState.stats=proxy::Stats();}
    if(!serviceInstalled)serviceProfileLoaded=false;
    if(serviceInstalled&&!wasInstalled&&action==ServiceAction::Poll){serviceProfileLoaded=false;serviceBanner=L"Обнаружена служба Windows. Нажмите «Обновить профиль», чтобы подключить окно к её настройкам.";serviceBannerError=false;}
    if(reply.profileLoaded) {
        const bool proxyOnly=action==ServiceAction::SaveProxy||action==ServiceAction::SaveProxyStart;
        const bool mtOnly=action==ServiceAction::SaveTelegram||action==ServiceAction::SaveTelegramStart;
        if(!mtOnly)applyProxyProfile(reply.profile);
        if(!proxyOnly)applyTelegramProfile(reply.profile);
        serviceFirewall=reply.profile.manageFirewall;check(ServiceFirewall,serviceFirewall);check(AutoWindows,false);serviceProfileLoaded=true;serviceOptionsDirty=false;
    }
    if(serviceMode()) {
        recordStats(serviceState.reachable?serviceState.stats:proxy::Stats());
        if(serviceState.reachable)for(const auto& event:serviceState.events){lastServiceEvent=(std::max)(lastServiceEvent,event.id);addJournal(event.level=="error"?L"Ошибка":event.level=="warning"?L"Внимание":L"Инфо",wide(event.message),wide(event.time));}
        if(!serviceState.reachable&&serviceState.scmState!=SERVICE_STOPPED){serviceBanner=L"Нет подтверждённой связи со службой. "+wide(reply.stateError.empty()?reply.state.error:reply.stateError);serviceBannerError=true;if(wasReachable)addJournal(L"Внимание",L"Связь со службой потеряна; состояние компонентов неизвестно.");}
        if(serviceState.reachable&&!wasReachable)addJournal(L"Инфо",L"Установлена связь со службой Windows.");
    }
    if(action!=ServiceAction::Poll) {
        if(!reply.ok||!reply.error.empty()) {
            serviceBanner=wide(reply.error.empty()?reply.stateError:reply.error);if(serviceBanner.empty())serviceBanner=L"Операция службы не завершена.";
            serviceBannerError=true;addJournal(L"Ошибка",serviceBanner);
            if(action==ServiceAction::SaveTelegram||action==ServiceAction::SaveTelegramStart)setMtBanner(serviceBanner,true);else setBanner(serviceBanner,true);
        }else {
            serviceBannerError=false;
            if(action==ServiceAction::Install)serviceBanner=L"Служба установлена. Переносим работающие компоненты…";
            else if(action==ServiceAction::Remove){serviceBanner=L"Служба удалена. Защищённый профиль и данные сохранены; портативный запуск доступен вручную.";setBanner(serviceBanner);}
            else if(action==ServiceAction::Stop)serviceBanner=L"Служба остановлена. Её подключения закрыты.";
            else if(action==ServiceAction::Start||action==ServiceAction::ActivateInstalled)serviceBanner=L"Служба запущена. Доступность портов проверьте в клиенте.";
            else if(action==ServiceAction::SaveProxy||action==ServiceAction::SaveProxyStart){serviceBanner=L"Параметры прокси сохранены в службе.";setBanner(serviceBanner);}
            else if(action==ServiceAction::SaveTelegram||action==ServiceAction::SaveTelegramStart){serviceBanner=L"Параметры MTProto сохранены в службе.";setMtBanner(serviceBanner);}
            else if(action==ServiceAction::StopProxy){serviceBanner=L"Прокси в службе остановлен.";setBanner(serviceBanner);}
            else if(action==ServiceAction::StopTelegram){serviceBanner=L"MTProto в службе остановлен.";setMtBanner(serviceBanner);}
            else serviceBanner=serviceMode()?L"Загружен действующий профиль службы.":L"Служба не установлена. Доступен портативный режим.";
        }
    }
    if(action==ServiceAction::ActivateInstalled&&!legacyStartupWarning.empty()){serviceBanner+=L"\n"+legacyStartupWarning;serviceBannerError=true;}
    clearProfile(reply.profile);
    if(action==ServiceAction::Install&&reply.ok) {
        // install() has staged a protected profile and a stopped service before local engines are released.
        legacyStartupWarning.clear();if(!disableLegacyWindowStartup(legacyStartupWarning))addJournal(L"Внимание",legacyStartupWarning);check(AutoWindows,false);
        server.stop();mtController.stop();mtLastRunning=false;lastRunning=false;collectCoreEvents();service_host::releaseStandaloneOwnership();
        serviceInstalled=true;serviceProfileLoaded=false;
        ServiceRequest activate;activate.action=ServiceAction::ActivateInstalled;activate.restoreProxy=reply.request.restoreProxy;activate.restoreMt=reply.request.restoreMt;
        queueServiceRequest(std::move(activate));selectPage(Service);return;
    }
    if(serviceInitialDiscovery&&action==ServiceAction::Discover&&scmKnown) {
        serviceInitialDiscovery=false;
        if(!serviceMode()) {
            standaloneAutoProxy=loadConfig();standaloneAutoMt=loadMtConfig();refreshServiceDefaults();
            if(standaloneAutoProxy)startServer(true);else if(configured.user.empty()||bannerError)selectPage(fieldErrorPage);
            if(standaloneAutoMt){startMt(true);if(!server.running())selectPage(Telegram);}
            else if(!mtConfigured.secret.empty()&&configured.user.empty())selectPage(Telegram);
        }else if(serviceMode()){selectPage(serviceProfileLoaded?Overview:Service);if(serviceProfileLoaded){setBanner(L"Подключено к службе Windows. Окно можно закрыть без остановки прокси.");setMtBanner(L"Загружены настройки MTProto из профиля службы.");}}
        else selectPage(Service);
    }
    if(wasInstalled&&!serviceMode()){lastServiceEvent=0;previous=proxy::Stats();uploadHistory.clear();downloadHistory.clear();}
    if(queuedServiceRequest){ServiceRequest next=std::move(*queuedServiceRequest);queuedServiceRequest.reset();queueServiceRequest(std::move(next));}
    refreshServiceControls();updateState();updateMtState();layoutContent();
}
void requestInstallService() {
    if(serviceMode()||serviceMutationBusy()||!serviceChecked||!serviceStatusKnown)return;
    if(certGenerating){alert(L"Дождитесь завершения создания сертификата.",MB_ICONINFORMATION);return;}
    ServiceRequest request;request.action=ServiceAction::Install;std::wstring error;
    request.profile.proxyAutoStart=checked(ServiceProxyAuto);request.profile.mtAutoStart=checked(ServiceMtAuto);request.profile.manageFirewall=checked(ServiceFirewall);
    const bool unusedProxy=!request.profile.proxyAutoStart&&!server.running()&&getText(control(User)).empty()&&getText(control(Password)).empty();
    if(!fields(request.profile.proxy,error,unusedProxy)){setBanner(error,true);selectPage(fieldErrorPage);alert(error,MB_ICONWARNING);clearProfile(request.profile);return;}
    request.restoreProxy=server.running();request.restoreMt=mtController.running();
    const bool haveMtSecret=!getText(control(MtSecret)).empty();std::wstring domain;
    if(haveMtSecret||request.profile.mtAutoStart||request.restoreMt) {
        if(!mtFields(request.profile.mt,domain,error)){setMtBanner(error,true);selectPage(Telegram);alert(error,MB_ICONWARNING);clearProfile(request.profile);return;}
    }else {
        unsigned port=0;if(readUnsigned(getText(control(MtPort)),65535,port)&&port)request.profile.mt.listenPort=static_cast<unsigned short>(port);
        request.profile.mt.bindAddress=ascii(getText(control(MtBind)));request.profile.mt.publicHost=ascii(getText(control(MtPublicHost)));domain=getText(control(MtDomain));
    }
    request.profile.tlsDomain=utf8(domain);
    std::wstring selectedPorts;
    auto appendPort=[&](const wchar_t* label,unsigned port){if(!selectedPorts.empty())selectedPorts+=L", ";selectedPorts+=std::wstring(label)+L" "+number(port);};
    const proxy::Config& p=request.profile.proxy;
    if(!p.user.empty()&&!p.password.empty()&&p.bindAddress.compare(0,4,"127.")!=0) {
        if(p.enableSocks)appendPort(L"SOCKS5 TCP",p.socksPort);
        if(p.enableHttp)appendPort(L"HTTP TCP",p.httpPort);
        if(p.enableChainSocks)appendPort(L"цепочка SOCKS5 TCP",p.chainSocksPort);
        if(p.enableChainHttp)appendPort(L"цепочка HTTP TCP",p.chainHttpPort);
        if(p.enableHttps)appendPort(L"HTTPS TCP",p.httpsPort);
        if(p.enableSocksTls)appendPort(L"SOCKS/TLS TCP",p.socksTlsPort);
        if(p.enableSocksUdp&&(p.enableSocks||(p.enableChainSocks&&p.upstreamType=="socks5")||(p.enableSocksTls&&(!p.tlsUseChain||p.upstreamType=="socks5")))){if(!selectedPorts.empty())selectedPorts+=L", ";selectedPorts+=L"SOCKS5 UDP "+number(p.udpPortMin)+L"–"+number(p.udpPortMax);}
    }
    if(!request.profile.mt.secret.empty()&&request.profile.mt.bindAddress.compare(0,4,"127.")!=0)appendPort(L"MTProto TCP",request.profile.mt.listenPort);
    if(selectedPorts.empty())selectedPorts=L"Внешние входящие порты не выбраны; для loopback правила не требуются";
    std::wstring prompt=L"Установить и запустить службу Windows от LocalSystem?\n\nПрограмма и компоненты будут скопированы в защищённую папку Program Files, профиль — в ProgramData. Сама служба запускается после перезагрузки без входа в Windows.\n\n";
    prompt+=L"Автозапуск прокси: "+std::wstring(request.profile.proxyAutoStart?L"да":L"нет")+L". Автозапуск MTProto: "+(request.profile.mtAutoStart?L"да":L"нет")+L".\n\n";
    if(request.profile.manageFirewall)prompt+=L"Порты правил: "+selectedPorts+L".\n\n";
    prompt+=request.profile.manageFirewall?L"Будут добавлены входящие правила брандмауэра только для выбранных портов и компонентов службы. Другие правила и RDP не меняются.\n\n":L"Правила брандмауэра не будут добавлены; разрешения для новой папки компонентов нужно настроить отдельно.\n\n";
    prompt+=L"Текущие локальные подключения будут закрыты только после успешной установки. Работавшие компоненты будут запущены службой. Исходный proxy.ini сохранится. Автозапуск старого окна ProxyServer.exe будет отключён.";
    if(MessageBoxW(window,prompt.c_str(),L"Установка службы Proxy Server",MB_YESNO|MB_ICONINFORMATION|MB_DEFBUTTON2)!=IDYES){clearProfile(request.profile);return;}
    queueServiceRequest(std::move(request));
}
void requestServiceRefresh() {
    if(serviceMutationBusy())return;
    if((dirty||mtDirty)&&MessageBoxW(window,L"Загрузить действующий профиль службы и заменить несохранённые изменения в окне?",AppName,MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2)!=IDYES)return;
    ServiceRequest request;request.action=serviceMode()?ServiceAction::Reload:ServiceAction::Discover;queueServiceRequest(std::move(request));
}
void requestServiceAction(ServiceAction action) {
    if(serviceMutationBusy()||!serviceMode())return;
    if(action==ServiceAction::Stop&&MessageBoxW(window,L"Остановить службу и закрыть все её соединения прокси и MTProto?",AppName,MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2)!=IDYES)return;
    if(action==ServiceAction::Remove&&MessageBoxW(window,L"Удалить службу Windows? Она будет остановлена, активные подключения закроются. Защищённый профиль и данные останутся на диске.",AppName,MB_YESNO|MB_ICONWARNING|MB_DEFBUTTON2)!=IDYES)return;
    ServiceRequest request;request.action=action;queueServiceRequest(std::move(request));
}
void startMt(bool fromLoaded) {
    if(!canUseBackend()||telegramRunning())return;
    mtproto::Config c;std::wstring domain,message;
    if(serviceMode()){saveMtFields(c,true);clearString(c.secret);return;}
    if(fromLoaded){if(!mtFields(c,domain,message)){setMtBanner(message,true);clearString(c.secret);return;}}
    else if(!saveMtFields(c)){clearString(c.secret);return;}
    std::string error;bool ok=false;
    if(!service_host::acquireStandaloneOwnership(error)){clearString(c.secret);setMtBanner(wide(error),true);alert(wide(error));return;}
    try{ok=mtController.start(appDir+L"components\\mtg.exe",c,error);}catch(...){error=u8"Не удалось создать процесс MTProto: недостаточно ресурсов.";}clearString(c.secret);
    if(!ok){if(!server.running())service_host::releaseStandaloneOwnership();setMtBanner(mtError(error),true);addJournal(L"Ошибка",L"MTProto не запущен: "+mtError(error));alert(mtError(error));updateMtState();return;}
    mtLastRunning=true;setMtBanner(L"Процесс MTProto запущен. Первый запуск может занять время; подключение проверьте в Telegram по ссылке.");addJournal(L"Инфо",L"Запущен отдельный процесс MTProto. Готовность из интернета проверяется клиентом Telegram.");updateMtState();layoutContent();
}
void stopMt() {
    if(!canUseBackend())return;
    if(serviceMode()){ServiceRequest request;request.action=ServiceAction::StopTelegram;queueServiceRequest(std::move(request));return;}
    mtController.stop();mtLastRunning=false;if(!server.running())service_host::releaseStandaloneOwnership();setMtBanner(L"MTProto остановлен. Можно изменить параметры.");addJournal(L"Инфо",L"Процесс MTProto остановлен.");updateMtState();
}
void generateMtSecret() {
    std::string secret,error;std::string domain=ascii(getText(control(MtDomain)));
    if(!mtproto::generateSecret(domain,secret,error)){setMtBanner(mtError(error),true);alert(mtError(error),MB_ICONWARNING);return;}
    setText(MtSecret,wide(secret));clearString(secret);mtDirty=true;setMtBanner(L"Создан новый секрет. После его сохранения старые ссылки подключения больше не подходят.");updateMtState();
}
void copyMtLink() {
    mtproto::Config c;std::wstring domain,error;if(!mtFields(c,domain,error)){setMtBanner(error,true);clearString(c.secret);alert(error,MB_ICONWARNING);return;}
    std::string link=mtproto::buildTelegramLink(c);clearString(c.secret);if(link.empty()){setMtBanner(L"Укажите внешний IP или домен VDS для ссылки подключения.",true);return;}
    std::wstring text=wide(link);clearString(link);SIZE_T bytes=(text.size()+1)*sizeof(wchar_t);HGLOBAL memory=GlobalAlloc(GMEM_MOVEABLE,bytes);if(!memory){setMtBanner(L"Недостаточно памяти для буфера обмена.",true);return;}void* data=GlobalLock(memory);if(!data){GlobalFree(memory);return;}memcpy(data,text.c_str(),bytes);GlobalUnlock(memory);SecureZeroMemory(&text[0],text.size()*sizeof(wchar_t));
    if(!OpenClipboard(window)){GlobalFree(memory);setMtBanner(L"Буфер обмена занят. Повторите копирование.",true);return;}EmptyClipboard();if(!SetClipboardData(CF_UNICODETEXT,memory)){GlobalFree(memory);CloseClipboard();setMtBanner(L"Не удалось скопировать ссылку.",true);return;}CloseClipboard();setMtBanner(L"Ссылка скопирована. Откройте её в Telegram; не публикуйте секрет в открытом доступе.");
}
void updateState() {
    const bool on=proxyRunning(),available=canUseBackend();
    SetWindowTextW(toggleButton,engineStateUnknown()?L"Прокси: нет связи":on?L"Прокси: остановить":L"Прокси: запустить");EnableWindow(toggleButton,available);
    int locked[]={User,Password,GeneratePassword,EnableSocks,EnableHttp,SocksPort,HttpPort,BindAddress,AllowIp,AutoProxy,AutoWindows,CloseTray,MaxConnections,ConnectTimeout,IdleTimeout,EnableChainSocks,EnableChainHttp,ChainSocksPort,ChainHttpPort,UpstreamType,UpstreamHost,UpstreamPort,UpstreamUser,UpstreamPassword,EnableHttps,HttpsPort,EnableSocksTls,SocksTlsPort,TlsCert,TlsKey,BrowseTlsCert,BrowseTlsKey,TlsCertHost,GenerateTlsCert,TlsUseChain,DnsServer,EnableDns,DnsPort,SocksUdp,UdpPortMin,UdpPortMax,Save,SaveStart};
    for(int id:locked)EnableWindow(control(id),available&&!on);
    if(available&&!on){EnableWindow(control(SocksPort),checked(EnableSocks));EnableWindow(control(HttpPort),checked(EnableHttp));EnableWindow(control(ChainSocksPort),checked(EnableChainSocks));EnableWindow(control(ChainHttpPort),checked(EnableChainHttp));EnableWindow(control(HttpsPort),checked(EnableHttps));EnableWindow(control(SocksTlsPort),checked(EnableSocksTls));EnableWindow(control(DnsPort),checked(EnableDns));EnableWindow(control(UdpPortMin),checked(SocksUdp));EnableWindow(control(UdpPortMax),checked(SocksUdp));}
    SetWindowTextW(control(GenerateTlsCert),certGenerating?L"Создание…":L"Создать сертификат");
    if(certGenerating){int lockedCert[]={TlsCert,TlsKey,BrowseTlsCert,BrowseTlsKey,TlsCertHost,GenerateTlsCert};for(int id:lockedCert)EnableWindow(control(id),FALSE);}
    if(lastRunning!=on){lastRunning=on;InvalidateRect(content,nullptr,TRUE);InvalidateRect(toggleButton,nullptr,TRUE);}
    if(trayPresent){tray.uFlags=NIF_TIP;std::wstring tip=L"Proxy Server — ";tip+=engineStateUnknown()?L"состояние неизвестно":L"прокси: "+std::wstring(on?L"вкл":L"выкл")+L", MTProto: "+(telegramRunning()?L"вкл":L"выкл");if(serviceMode())tip+=L" (служба)";copyBuffer(tray.szTip,tip.c_str());Shell_NotifyIconW(NIM_MODIFY,&tray);}
    refreshServiceControls();
}
void pollCertificate() {
    if(!certGenerating)return;
    certProcess.poll();if(certProcess.running())return;certGenerating=false;
    std::wstring cert=certOutputDir+L"\\cert.pem",key=certOutputDir+L"\\key.pem";
    if(certProcess.lastExitCode()==0&&GetFileAttributesW(cert.c_str())!=INVALID_FILE_ATTRIBUTES&&GetFileAttributesW(key.c_str())!=INVALID_FILE_ATTRIBUTES){setText(TlsCert,cert);setText(TlsKey,key);dirty=true;setBanner(L"Сертификат создан. Сохраните настройки; клиент должен доверять cert.pem. Закрытый key.pem оставьте на VDS.");addJournal(L"Инфо",L"Создан отдельный TLS-сертификат. Хранилище доверенных сертификатов Windows не изменялось.");}
    else{setBanner(L"Сертификат не создан. "+wide(certProcess.lastError()),true);addJournal(L"Ошибка",L"Не удалось создать TLS-сертификат. "+wide(certProcess.lastError()));}
}
void generateCertificate() {
    if(certGenerating)return;
    std::wstring host=getText(control(TlsCertHost));if(host.empty()){setBanner(L"Укажите IP VDS или домен для нового сертификата.",true);return;}
    std::wstring directory=appDir+L"certificates";if(!CreateDirectoryW(directory.c_str(),nullptr)&&GetLastError()!=ERROR_ALREADY_EXISTS){alert(L"Не удалось создать папку сертификатов. "+systemError(GetLastError()));return;}
    HCRYPTPROV provider=0;BYTE random[8]={};if(!CryptAcquireContextW(&provider,nullptr,nullptr,PROV_RSA_AES,CRYPT_VERIFYCONTEXT|CRYPT_SILENT)){alert(L"Не удалось получить генератор случайных чисел Windows.");return;}
    BOOL randomOk=CryptGenRandom(provider,sizeof(random),random);CryptReleaseContext(provider,0);if(!randomOk){alert(L"Не удалось создать уникальную папку сертификата.");return;}
    const wchar_t* hex=L"0123456789abcdef";std::wstring suffix;for(BYTE byte:random){suffix+=hex[byte>>4];suffix+=hex[byte&15];}SecureZeroMemory(random,sizeof(random));
    SYSTEMTIME t={};GetLocalTime(&t);wchar_t date[48]={};swprintf(date,48,L"%04u%02u%02u-%02u%02u%02u-",t.wYear,t.wMonth,t.wDay,t.wHour,t.wMinute,t.wSecond);
    certOutputDir=directory+L"\\"+date+suffix;std::string error;
    if(!certProcess.start(appDir+L"components\\proxy-cert.exe",{L"--host",host,L"--out",certOutputDir},"",error)){setBanner(L"Не удалось запустить генератор сертификата. "+wide(error),true);alert(L"Не удалось запустить генератор сертификата. "+wide(error));return;}
    certGenerating=true;setBanner(L"Создаётся новый сертификат…");int lockedCert[]={TlsCert,TlsKey,BrowseTlsCert,BrowseTlsKey,TlsCertHost,GenerateTlsCert};for(int id:lockedCert)EnableWindow(control(id),FALSE);SetWindowTextW(control(GenerateTlsCert),L"Создание…");
}
void sample() {
    consumeServiceReply();pollCertificate();
    if(!serviceMode()) {
        mtController.poll();
        if(mtLastRunning&&!mtController.running()){mtLastRunning=false;std::wstring error=wide(mtController.lastError());setMtBanner(error.empty()?L"Процесс MTProto завершился. Подробности доступны в журнале.":error,true);addJournal(L"Ошибка",L"Процесс MTProto завершился. "+error);}
        recordStats(server.stats());collectCoreEvents();
        if(lastRunning&&!server.running()&&!server.lastError().empty())setBanner(L"Сервер остановился с ошибкой: "+wide(server.lastError()),true);
        if(!server.running()&&!mtController.running())service_host::releaseStandaloneOwnership();
    }
    const ULONGLONG now=GetTickCount64();
    if(serviceChecked&&!serviceWorkerActive&&!queuedServiceRequest&&now-lastServicePoll>=2000){lastServicePoll=now;ServiceRequest request;request.action=serviceInitialDiscovery?ServiceAction::Discover:ServiceAction::Poll;queueServiceRequest(std::move(request));}
    updateMtState();updateState();
    if(currentPage==Overview||currentPage==Journal||currentPage==Service||currentPage==Telegram)InvalidateRect(content,nullptr,FALSE);
}
bool saveFields(proxy::Config& c,bool startInService=false) {
    if(!canUseBackend())return false;
    std::wstring error;if(!fields(c,error)){setBanner(error,true);selectPage(fieldErrorPage);alert(error,MB_ICONWARNING);return false;}
    if(serviceMode()) {
        if(!saveGuiPreferences(error)){setBanner(error,true);alert(error);return false;}
        ServiceRequest request;request.action=startInService?ServiceAction::SaveProxyStart:ServiceAction::SaveProxy;request.profile.proxy=c;request.profile.proxyAutoStart=checked(AutoProxy);queueServiceRequest(std::move(request));return false;
    }
    if(!saveConfig(c,error)){setBanner(error,true);alert(error);return false;}
    clearString(configured.password);clearString(configured.upstreamPassword);configured=c;clearString(configured.password);clearString(configured.upstreamPassword);closeToTray=checked(CloseTray);dirty=false;setBanner(L"Настройки сохранены.");addJournal(L"Инфо",L"Параметры программы сохранены.");return true;
}
void startServer(bool fromLoaded) {
    if(!canUseBackend()||proxyRunning())return;
    proxy::Config c;std::wstring err;
    if(serviceMode()){saveFields(c,true);clearString(c.password);clearString(c.upstreamPassword);return;}
    if(fromLoaded){if(!fields(c,err)){setBanner(err,true);selectPage(fieldErrorPage);clearString(c.password);clearString(c.upstreamPassword);return;}}
    else if(!saveFields(c)){clearString(c.password);clearString(c.upstreamPassword);return;}
    std::string error;bool started=false;
    if(!service_host::acquireStandaloneOwnership(error)){clearString(c.password);clearString(c.upstreamPassword);setBanner(wide(error),true);alert(wide(error));return;}
    try { started=server.start(c,error); }catch(...){error=u8"Недостаточно ресурсов для запуска.";}
    clearString(c.password);clearString(c.upstreamPassword);
    if(!started){if(!mtController.running())service_host::releaseStandaloneOwnership();setBanner(configError(error),true);addJournal(L"Ошибка",L"Запуск сервера не удался: "+wide(error));updateState();alert(configError(error));return;}
    previous=proxy::Stats();lastSample=GetTickCount64();sessionStarted=lastSample;uploadHistory.clear();downloadHistory.clear();
    setBanner(L"Прокси запущен. Для подключения используйте IP VDS и выбранный порт.");selectPage(Overview);sample();
}
void stopServer() {
    if(!canUseBackend())return;
    if(serviceMode()){ServiceRequest request;request.action=ServiceAction::StopProxy;queueServiceRequest(std::move(request));return;}
    server.stop();collectCoreEvents();if(!mtController.running())service_host::releaseStandaloneOwnership();setBanner(L"Сервер остановлен. Можно изменить настройки.");updateState();sample();
}
void generatePassword() {
    HCRYPTPROV provider=0;if(!CryptAcquireContextW(&provider,nullptr,nullptr,PROV_RSA_AES,CRYPT_VERIFYCONTEXT|CRYPT_SILENT)){alert(L"Не удалось получить генератор случайных чисел Windows.");return;}
    BYTE bytes[24]={};BOOL ok=CryptGenRandom(provider,sizeof(bytes),bytes);CryptReleaseContext(provider,0);
    if(!ok){alert(L"Не удалось создать пароль.");return;}
    const wchar_t* alphabet=L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";wchar_t password[25]={};for(int i=0;i<24;++i)password[i]=alphabet[bytes[i]&63];setText(Password,password);SecureZeroMemory(password,sizeof(password));SecureZeroMemory(bytes,sizeof(bytes));dirty=true;setBanner(L"Создан случайный пароль из 24 символов. Сохраните настройки и внесите его в клиент.");
}
std::wstring journalText() {
    std::wstring s=L"Proxy Server 2.1 — журнал\r\n";for(const auto& r:journalRows)s+=r.time+L" ["+r.level+L"] "+r.message+L"\r\n";return s;
}
bool protectedApplicationFolder() { return serviceMode()&&!serviceState.installDir.empty()&&_wcsicmp(appDir.c_str(),(serviceState.installDir+L"\\").c_str())==0; }
void copyFolderPath(const std::wstring& path) {
    if(path.empty())return;
    const SIZE_T bytes=(path.size()+1)*sizeof(wchar_t);HGLOBAL memory=GlobalAlloc(GMEM_MOVEABLE,bytes);
    if(!memory){alert(L"Недостаточно памяти для буфера обмена.");return;}
    void* destination=GlobalLock(memory);if(!destination){GlobalFree(memory);alert(L"Не удалось подготовить буфер обмена.");return;}
    memcpy(destination,path.c_str(),bytes);GlobalUnlock(memory);
    if(!OpenClipboard(window)){GlobalFree(memory);alert(L"Буфер обмена занят. Повторите копирование.");return;}
    EmptyClipboard();if(!SetClipboardData(CF_UNICODETEXT,memory)){GlobalFree(memory);CloseClipboard();alert(L"Не удалось скопировать путь.");return;}
    CloseClipboard();serviceBanner=L"Путь скопирован. Права доступа к папке не изменялись.";serviceBannerError=false;setBanner(serviceBanner);InvalidateRect(content,nullptr,FALSE);
}
void copyJournal() {
    auto text=journalText();SIZE_T size=(text.size()+1)*sizeof(wchar_t);HGLOBAL data=GlobalAlloc(GMEM_MOVEABLE,size);if(!data)return;void* memory=GlobalLock(data);if(!memory){GlobalFree(data);return;}memcpy(memory,text.c_str(),size);GlobalUnlock(data);
    if(!OpenClipboard(window)){GlobalFree(data);alert(L"Буфер обмена сейчас занят. Повторите попытку.");return;}EmptyClipboard();if(!SetClipboardData(CF_UNICODETEXT,data))GlobalFree(data);CloseClipboard();setBanner(L"Журнал скопирован.");
}
void exportJournal() {
    wchar_t file[32768]=L"ProxyServer-log.txt";OPENFILENAMEW ofn={};ofn.lStructSize=sizeof(ofn);ofn.hwndOwner=window;ofn.lpstrFilter=L"Текстовый файл (*.txt)\0*.txt\0Все файлы\0*.*\0";ofn.lpstrFile=file;ofn.nMaxFile=32768;ofn.lpstrDefExt=L"txt";ofn.Flags=OFN_OVERWRITEPROMPT|OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR;ofn.lpstrTitle=L"Сохранить журнал";
    if(!GetSaveFileNameW(&ofn))return;
    std::string data="\xEF\xBB\xBF"+utf8(journalText());std::wstring error;if(!atomicWrite(file,data.data(),static_cast<DWORD>(data.size()),error))alert(error);else setBanner(L"Журнал сохранён.");
}
void browseTls(bool key) {
    std::wstring current=getText(control(key?TlsKey:TlsCert));std::vector<wchar_t> path(32768);if(current.size()<path.size())std::copy(current.begin(),current.end(),path.begin());
    OPENFILENAMEW dialog={};dialog.lStructSize=sizeof(dialog);dialog.hwndOwner=window;dialog.lpstrFilter=L"PEM / CRT / KEY\0*.pem;*.crt;*.key\0Все файлы\0*.*\0";dialog.lpstrFile=path.data();dialog.nMaxFile=static_cast<DWORD>(path.size());dialog.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR;dialog.lpstrTitle=key?L"Выберите закрытый ключ TLS":L"Выберите сертификат TLS";
    if(GetOpenFileNameW(&dialog))setText(key?TlsKey:TlsCert,path.data());
}
void showHelp() {
    MessageBoxW(window,
      L"SOCKS5 / HTTP: задайте логин, пароль и порты в «Настройках», затем нажмите «Сохранить и запустить».\n\n"
      L"Цепочка: отдельные порты через внешний SOCKS5 или HTTP-прокси. Автоматического перехода напрямую нет.\n\n"
      L"TLS / DNS: отдельные HTTPS и SOCKS/TLS порты, сертификат и ключ; DNS по выбору. Локальный DNS доступен только на 127.0.0.1. SOCKS5 UDP включается отдельно.\n\n"
      L"Telegram: настройте MTProto, создайте секрет, запустите его своей кнопкой и скопируйте ссылку. Секрет заменяет логин и пароль.\n\n"
      L"Брандмауэр: разрешение Windows нужно сетевым компонентам gost.exe и mtg.exe. В служебном режиме можно разрешить только выбранные порты. Сетевые профили, чужие правила и RDP не меняются.\n\n"
      L"Вкладка «Служба» устанавливает отдельную службу Windows с запуском без входа в систему. Окно и выход из учётной записи её не останавливают. В портативном режиме «Выход» завершает сетевые компоненты.\n\n"
      L"Полная инструкция — README.md в папке программы.",
      L"Proxy Server 2.1 — помощь",MB_OK|MB_ICONINFORMATION);
}

void reveal() { ShowWindow(window,SW_RESTORE);SetForegroundWindow(window); }
void addTray() {
    tray={};tray.cbSize=sizeof(tray);tray.hWnd=window;tray.uID=1;tray.uFlags=NIF_ICON|NIF_MESSAGE|NIF_TIP;tray.uCallbackMessage=TrayMessage;tray.hIcon=appIcon;copyBuffer(tray.szTip,L"Proxy Server");trayPresent=Shell_NotifyIconW(NIM_ADD,&tray)!=FALSE;updateState();
}
void hideWindow() {
    if(!trayPresent){ShowWindow(window,SW_MINIMIZE);return;}ShowWindow(window,SW_HIDE);
    if(firstHide){firstHide=false;tray.uFlags=NIF_INFO;copyBuffer(tray.szInfoTitle,L"Proxy Server продолжает работать");copyBuffer(tray.szInfo,serviceMode()?L"Откройте окно щелчком по значку в трее. Служба продолжает работу независимо от окна.":L"Откройте окно щелчком по значку в трее. Для завершения выберите «Выход».");tray.dwInfoFlags=NIIF_INFO;Shell_NotifyIconW(NIM_MODIFY,&tray);}
}
void requestExit() {
    if(serviceMutationBusy()){alert(L"Дождитесь завершения операции службы, затем закройте окно.",MB_ICONINFORMATION);return;}
    if((server.running()||mtController.running())&&MessageBoxW(window,L"Завершить программу, MTProto и закрыть активные подключения?",AppName,MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2)!=IDYES)return;
    if((dirty||mtDirty)&&MessageBoxW(window,L"В настройках есть несохранённые изменения. Выйти без сохранения?",AppName,MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2)!=IDYES)return;
    quitting=true;DestroyWindow(window);
}
void showTrayMenu() {
    POINT p;GetCursorPos(&p);HMENU m=CreatePopupMenu();AppendMenuW(m,MF_STRING,TrayOpen,L"Открыть Proxy Server");AppendMenuW(m,MF_SEPARATOR,0,nullptr);
    AppendMenuW(m,MF_STRING|(!canUseBackend()||proxyRunning()?MF_GRAYED:0),TrayStart,L"Запустить SOCKS / HTTP");AppendMenuW(m,MF_STRING|(canUseBackend()&&proxyRunning()?0:MF_GRAYED),TrayStop,L"Остановить SOCKS / HTTP");AppendMenuW(m,MF_SEPARATOR,0,nullptr);
    AppendMenuW(m,MF_STRING|(!canUseBackend()||telegramRunning()?MF_GRAYED:0),TrayMtStart,L"Запустить MTProto");AppendMenuW(m,MF_STRING|(canUseBackend()&&telegramRunning()?0:MF_GRAYED),TrayMtStop,L"Остановить MTProto");AppendMenuW(m,MF_SEPARATOR,0,nullptr);AppendMenuW(m,MF_STRING,TrayExit,L"Выход");
    SetForegroundWindow(window);TrackPopupMenu(m,TPM_RIGHTBUTTON,p.x,p.y,0,window,nullptr);DestroyMenu(m);PostMessageW(window,WM_NULL,0,0);
}
void onCommand(int id,int notification) {
    if(id>=NavOverview&&id<=NavJournal){selectPage(static_cast<Page>(id-NavOverview));return;}
    switch(id) {
      case Help:showHelp();return;
      case Exit:case TrayExit:requestExit();return;
      case Toggle:if(proxyRunning())stopServer();else startServer();return;
      case TrayOpen:reveal();return;
      case TrayStart:startServer();return;
      case TrayStop:stopServer();return;
      case TrayMtStart:startMt();return;
      case TrayMtStop:stopMt();return;
      case BrowseTlsCert:browseTls(false);return;
      case BrowseTlsKey:browseTls(true);return;
      case GenerateTlsCert:generateCertificate();return;
      case MtToggle:if(telegramRunning())stopMt();else startMt();return;
      case MtSave:{mtproto::Config c;saveMtFields(c);clearString(c.secret);return;}
      case MtGenerate:generateMtSecret();return;
      case MtCopyLink:copyMtLink();return;
      case MtShowSecret:SendMessageW(control(MtSecret),EM_SETPASSWORDCHAR,checked(MtShowSecret)?0:0x25CF,0);InvalidateRect(control(MtSecret),nullptr,TRUE);return;
      case Save:{proxy::Config c;if(saveFields(c))InvalidateRect(content,nullptr,FALSE);clearString(c.password);clearString(c.upstreamPassword);return;}
      case SaveStart:startServer();return;
      case ShowPassword:SendMessageW(control(Password),EM_SETPASSWORDCHAR,checked(ShowPassword)?0:0x25CF,0);InvalidateRect(control(Password),nullptr,TRUE);return;
      case ShowUpstreamPassword:SendMessageW(control(UpstreamPassword),EM_SETPASSWORDCHAR,checked(ShowUpstreamPassword)?0:0x25CF,0);InvalidateRect(control(UpstreamPassword),nullptr,TRUE);return;
      case GeneratePassword:generatePassword();return;
      case ExportLog:exportJournal();return;
      case CopyLog:copyJournal();return;
      case OpenFolder:if(protectedApplicationFolder())copyFolderPath(appDir);else ShellExecuteW(window,L"open",appDir.c_str(),nullptr,nullptr,SW_SHOWNORMAL);return;
      case ServiceInstall:requestInstallService();return;
      case ServiceRefresh:requestServiceRefresh();return;
      case ServiceStart:requestServiceAction(ServiceAction::Start);return;
      case ServiceStop:requestServiceAction(ServiceAction::Stop);return;
      case ServiceRemove:requestServiceAction(ServiceAction::Remove);return;
      case ServiceOpenData:copyFolderPath(serviceState.dataDir);return;
      case ServiceProxyAuto:case ServiceMtAuto:case ServiceFirewall:if(!loading)serviceOptionsDirty=true;return;
      default:break;
    }
    if(!loading&&!telegramRunning()&&id>=MtBind&&id<=MtAuto&&(notification==EN_CHANGE||notification==BN_CLICKED)){mtDirty=true;mtBanner.clear();
        if(id==MtSecret&&notification==EN_CHANGE){std::wstring parsed;std::string secret=ascii(getText(control(MtSecret)));if(secretDomainText(secret,parsed)){loading=true;setText(MtDomain,parsed);loading=false;}clearString(secret);}
        updateMtState();InvalidateRect(content,nullptr,FALSE);return;}
    if(!loading&&!proxyRunning()&&id>=User&&id<=UdpPortMax&&(notification==EN_CHANGE||notification==BN_CLICKED||notification==CBN_SELCHANGE)){dirty=true;banner.clear();updateState();InvalidateRect(content,nullptr,FALSE);}
}
void scrollContent(int code,int wheel=0) {
    SCROLLINFO si={};si.cbSize=sizeof(si);si.fMask=SIF_ALL;GetScrollInfo(content,SB_VERT,&si);
    int next=scrollY;if(wheel)next-=wheel;else switch(code){case SB_LINEUP:next-=28;break;case SB_LINEDOWN:next+=28;break;case SB_PAGEUP:next-=contentHeight-40;break;case SB_PAGEDOWN:next+=contentHeight-40;break;case SB_TOP:next=0;break;case SB_BOTTOM:next=si.nMax;break;case SB_THUMBTRACK:case SB_THUMBPOSITION:next=si.nTrackPos;break;default:return;}
    next=(std::max)(0,(std::min)(next,si.nMax-static_cast<int>(si.nPage)+1));if(next!=scrollY){scrollY=next;layoutContent();}
}
LRESULT CALLBACK contentProc(HWND hwnd,UINT message,WPARAM wp,LPARAM lp) {
    switch(message) {
      case WM_PAINT:{PAINTSTRUCT ps;HDC dc=BeginPaint(hwnd,&ps);RECT r;GetClientRect(hwnd,&r);HDC memory=CreateCompatibleDC(dc);HBITMAP bitmap=CreateCompatibleBitmap(dc,(std::max)(1,static_cast<int>(r.right)),(std::max)(1,static_cast<int>(r.bottom)));HGDIOBJ old=SelectObject(memory,bitmap);paintContent(memory);BitBlt(dc,0,0,r.right,r.bottom,memory,0,0,SRCCOPY);SelectObject(memory,old);DeleteObject(bitmap);DeleteDC(memory);EndPaint(hwnd,&ps);return 0;}
      case WM_ERASEBKGND:return 1;
      case WM_DRAWITEM:drawButton(reinterpret_cast<DRAWITEMSTRUCT*>(lp));return TRUE;
      case WM_COMMAND:onCommand(LOWORD(wp),HIWORD(wp));return 0;
      case WM_VSCROLL:scrollContent(LOWORD(wp));return 0;
      case WM_HSCROLL:{SCROLLINFO si={};si.cbSize=sizeof(si);si.fMask=SIF_ALL;GetScrollInfo(content,SB_HORZ,&si);int next=scrollX;switch(LOWORD(wp)){case SB_LINELEFT:next-=28;break;case SB_LINERIGHT:next+=28;break;case SB_PAGELEFT:next-=viewportWidth-40;break;case SB_PAGERIGHT:next+=viewportWidth-40;break;case SB_THUMBTRACK:case SB_THUMBPOSITION:next=si.nTrackPos;break;default:return 0;}scrollX=(std::max)(0,(std::min)(next,contentWidth-viewportWidth));layoutContent();return 0;}
      case WM_MOUSEWHEEL:scrollContent(0,GET_WHEEL_DELTA_WPARAM(wp)/WHEEL_DELTA*84);return 0;
      case WM_CTLCOLORSTATIC:case WM_CTLCOLORBTN:{HDC dc=reinterpret_cast<HDC>(wp);SetTextColor(dc,Text);SetBkColor(dc,White);return reinterpret_cast<LRESULT>(whiteBrush);}
      case WM_CTLCOLOREDIT:{HDC dc=reinterpret_cast<HDC>(wp);SetTextColor(dc,Text);SetBkColor(dc,White);return reinterpret_cast<LRESULT>(editBrush);}
      case WM_NOTIFY:break;
    }
    return DefWindowProcW(hwnd,message,wp,lp);
}
LRESULT CALLBACK windowProc(HWND hwnd,UINT message,WPARAM wp,LPARAM lp) {
    if(message==taskbarCreated&&taskbarCreated){trayPresent=false;addTray();return 0;}
    switch(message) {
      case WM_CREATE:window=hwnd;createControls();return 0;
      case WM_PAINT:{PAINTSTRUCT ps;HDC dc=BeginPaint(hwnd,&ps);paintMain(dc);EndPaint(hwnd,&ps);return 0;}
      case WM_ERASEBKGND:return 1;
      case WM_DRAWITEM:drawButton(reinterpret_cast<DRAWITEMSTRUCT*>(lp));return TRUE;
      case WM_COMMAND:onCommand(LOWORD(wp),HIWORD(wp));return 0;
      case WM_SIZE:if(wp==SIZE_MINIMIZED){if(closeToTray&&trayPresent)hideWindow();}else layoutMain();return 0;
      case WM_GETMINMAXINFO:{MINMAXINFO* info=reinterpret_cast<MINMAXINFO*>(lp);RECT work={};SystemParametersInfoW(SPI_GETWORKAREA,0,&work,0);info->ptMinTrackSize.x=(std::min)(px(905),static_cast<int>(work.right-work.left));info->ptMinTrackSize.y=(std::min)(px(540),static_cast<int>(work.bottom-work.top));return 0;}
      case WM_DPICHANGED:{dpi=HIWORD(wp);deleteFonts();createFonts();refreshFonts();RECT* suggested=reinterpret_cast<RECT*>(lp);SetWindowPos(hwnd,nullptr,suggested->left,suggested->top,suggested->right-suggested->left,suggested->bottom-suggested->top,SWP_NOZORDER|SWP_NOACTIVATE);layoutMain();return 0;}
      case WM_TIMER:if(wp==1)sample();return 0;
      case ServiceCompleteMessage:consumeServiceReply();return 0;
      case WM_MOUSEWHEEL:scrollContent(0,GET_WHEEL_DELTA_WPARAM(wp)/WHEEL_DELTA*84);return 0;
      case RevealMessage:reveal();return 0;
      case TrayMessage:if(lp==WM_LBUTTONUP||lp==WM_LBUTTONDBLCLK)reveal();else if(lp==WM_RBUTTONUP||lp==WM_CONTEXTMENU)showTrayMenu();return 0;
      case WM_CLOSE:if(closeToTray&&trayPresent&&!quitting)hideWindow();else requestExit();return 0;
      case WM_QUERYENDSESSION:return TRUE;
      case WM_ENDSESSION:if(wp){quitting=true;DestroyWindow(hwnd);}return 0;
      case WM_DESTROY:KillTimer(hwnd,1);certProcess.stop();mtController.stop();clearString(mtConfigured.secret);server.stop();service_host::releaseStandaloneOwnership();collectCoreEvents();if(trayPresent)Shell_NotifyIconW(NIM_DELETE,&tray);clearString(configured.password);clearString(configured.upstreamPassword);PostQuitMessage(0);return 0;
    }
    return DefWindowProcW(hwnd,message,wp,lp);
}
}

int WINAPI wWinMain(HINSTANCE inst,HINSTANCE,LPWSTR commandLine,int) {
    int serviceExit=0;if(service_host::dispatchIfService(commandLine,serviceExit))return serviceExit;
    instance=inst;
    // Manifest supplies per-monitor awareness on modern Windows; fallback supports older SDKs.
    SetProcessDPIAware();HDC screen=GetDC(nullptr);dpi=GetDeviceCaps(screen,LOGPIXELSX);ReleaseDC(nullptr,screen);if(!dpi)dpi=96;
    std::vector<wchar_t> exe(32768);DWORD len=GetModuleFileNameW(nullptr,exe.data(),static_cast<DWORD>(exe.size()));if(!len||len>=exe.size())return 1;exePath.assign(exe.data(),len);auto slash=exePath.find_last_of(L"\\/");appDir=slash==std::wstring::npos?L"":exePath.substr(0,slash+1);iniPath=appDir+L"proxy.ini";logPath=appDir+L"logs\\ProxyServer.log";
    HANDLE mutex=CreateMutexW(nullptr,FALSE,L"Local\\PrivateNativeProxyServerV2");if(!mutex)return 1;
    if(GetLastError()==ERROR_ALREADY_EXISTS){HWND existing=FindWindowW(AppClass,nullptr);if(existing){PostMessageW(existing,RevealMessage,0,0);SetForegroundWindow(existing);}else MessageBoxW(nullptr,L"Proxy Server 2.1 уже запускается или работает. Откройте окно из трея.",AppName,MB_OK|MB_ICONINFORMATION);CloseHandle(mutex);return 0;}
    std::string error;if(!proxy::networkInit(error)){MessageBoxW(nullptr,wide(error).c_str(),AppName,MB_OK|MB_ICONERROR);CloseHandle(mutex);return 1;}
    INITCOMMONCONTROLSEX cc={sizeof(cc),ICC_LISTVIEW_CLASSES|ICC_STANDARD_CLASSES};InitCommonControlsEx(&cc);
    editBrush=CreateSolidBrush(White);whiteBrush=CreateSolidBrush(White);bgBrush=CreateSolidBrush(Canvas);
    appIcon=static_cast<HICON>(LoadImageW(instance,MAKEINTRESOURCEW(101),IMAGE_ICON,0,0,LR_DEFAULTSIZE|LR_SHARED));if(!appIcon)appIcon=LoadIconW(nullptr,IDI_APPLICATION);
    WNDCLASSEXW contentClass={};contentClass.cbSize=sizeof(contentClass);contentClass.hInstance=instance;contentClass.lpfnWndProc=contentProc;contentClass.lpszClassName=ContentClass;contentClass.hCursor=LoadCursorW(nullptr,IDC_ARROW);contentClass.hbrBackground=bgBrush;RegisterClassExW(&contentClass);
    WNDCLASSEXW wc={};wc.cbSize=sizeof(wc);wc.hInstance=instance;wc.lpfnWndProc=windowProc;wc.lpszClassName=AppClass;wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);wc.hIcon=appIcon;wc.hIconSm=appIcon;
    if(!RegisterClassExW(&wc)){CloseHandle(mutex);return 1;}taskbarCreated=RegisterWindowMessageW(L"TaskbarCreated");
    RECT work={};SystemParametersInfoW(SPI_GETWORKAREA,0,&work,0);DWORD style=WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN;RECT r={0,0,px(1060),px(752)};AdjustWindowRectEx(&r,style,FALSE,WS_EX_CONTROLPARENT);
    int width=(std::min)(r.right-r.left,work.right-work.left),height=(std::min)(r.bottom-r.top,work.bottom-work.top);
    window=CreateWindowExW(WS_EX_CONTROLPARENT,AppClass,L"Proxy Server 2.1",style,work.left+(work.right-work.left-width)/2,work.top+(work.bottom-work.top-height)/2,width,height,nullptr,nullptr,instance,nullptr);
    if(!window){CloseHandle(mutex);return 1;}
    addTray();layoutMain();addJournal(L"Инфо",L"Программа открыта. Версия 2.1. Правила брандмауэра добавляются только по выбранной настройке службы.");
    loading=true;closeToTray=ini(L"close_to_tray",L"1")==L"1";check(CloseTray,closeToTray);check(AutoWindows,startupEnabled());setText(TlsCertHost,ini(L"tls_cert_name"));check(ServiceFirewall,true);loading=false;
    setBanner(L"Проверяем, установлена ли служба Windows…");
    updateState();updateMtState();SetTimer(window,1,1000,nullptr);
    ServiceRequest discovery;discovery.action=ServiceAction::Discover;queueServiceRequest(std::move(discovery));
    bool minimized=commandLine&&wcsstr(commandLine,L"--minimized")!=nullptr;
    if(minimized&&trayPresent)ShowWindow(window,SW_HIDE);else ShowWindow(window,SW_SHOW);
    UpdateWindow(window);
    MSG msg={};BOOL result;while((result=GetMessageW(&msg,nullptr,0,0))>0){if(!IsDialogMessageW(window,&msg)){TranslateMessage(&msg);DispatchMessageW(&msg);}}
    if(serviceWorker.joinable())serviceWorker.join();
    clearProfile(serviceReply.profile);clearProfile(serviceReply.request.profile);
    if(queuedServiceRequest)clearProfile(queuedServiceRequest->profile);
    certProcess.stop();mtController.stop();server.stop();service_host::releaseStandaloneOwnership();deleteFonts();if(editBrush)DeleteObject(editBrush);if(whiteBrush)DeleteObject(whiteBrush);if(bgBrush)DeleteObject(bgBrush);CloseHandle(mutex);
    // DNS work, if any, owns its State. Process teardown performs final Winsock cleanup.
    return result==-1?1:0;
}
