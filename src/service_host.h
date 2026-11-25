#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "proxy_core.h"
#include "mtproto_win.h"

// Windows service management and local, administrator-only IPC.
// Potentially blocking operations belong on the GUI's serialized worker.
namespace service_host {
struct Profile {
    proxy::Config proxy;
    mtproto::Config mt;
    bool proxyAutoStart = false;
    bool mtAutoStart = false;
    bool manageFirewall = true; // Explicit install choice; only this app's rules.
    std::string tlsDomain;
};
struct State {
    bool installed = false;
    bool reachable = false;
    std::uint32_t scmState = 0; // Windows SERVICE_* constant; 0 = not installed.
    bool proxyRunning = false;
    bool mtRunning = false;
    proxy::Stats stats;
    std::vector<proxy::Event> events;
    std::string proxyError, mtError, error;
    std::uint64_t proxyRestarts = 0, mtRestarts = 0;
    std::wstring installDir, dataDir;
};
enum class Command { StartProxy = 1, StopProxy = 2, StartTelegram = 3, StopTelegram = 4 };

bool isElevated();
bool dispatchIfService(const wchar_t* commandLine, int& exitCode);
// Returns a valid SCM snapshot even if the service is stopped/unreachable.
// reachable identifies a successful authenticated local IPC response.
bool getState(State& state, std::string& error, std::uint64_t afterEvent = 0);
bool loadProfile(Profile& profile, std::string& error);
// Creates an automatic-start service but leaves it stopped. Existing installs
// are not replaced; uninstall intentionally retains their protected data.
bool install(const Profile& profile, std::string& error);
bool startService(std::string& error);
bool stopService(std::string& error);
bool uninstall(std::string& error);
bool saveProxy(const proxy::Config& config, bool autoStart, std::string& error);
bool saveTelegram(const mtproto::Config& config, bool autoStart,
                  const std::string& tlsDomain, std::string& error);
bool command(Command command, std::string& error);

// Both standalone engines share one process-held global ownership object.
// Acquire before either standalone start; release after BOTH are stopped.
bool acquireStandaloneOwnership(std::string& error);
void releaseStandaloneOwnership();
}
