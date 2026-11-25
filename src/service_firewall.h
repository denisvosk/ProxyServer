#pragma once
#include "proxy_core.h"
#include "mtproto_win.h"
#include <string>
#include <vector>

// The service installer only manages its own inbound allow rules. It never
// changes firewall profiles, policy defaults, RDP, or another program's rules.
namespace service_firewall {
struct Rule {
    std::wstring name;
    std::wstring application;
    std::wstring localPorts;
    std::wstring localAddresses;
    std::wstring remoteAddresses;
    int protocol = 6;
};
const wchar_t* groupName();
const wchar_t* description();
std::wstring installationPrefix(const std::wstring& installDirectory);
bool makePlan(const proxy::Config& proxy, const mtproto::Config& mt,
              const std::wstring& installDirectory, bool includeMTProto,
              std::vector<Rule>& rules, std::string& error);
// Stage all new rules before removing superseded rules. On failure, restore
// the previous owned rules and remove newly staged rules (report any rollback
// error explicitly). Pre-existing unrelated rules are never mutated.
bool apply(const proxy::Config& proxy, const mtproto::Config& mt,
           const std::wstring& installDirectory, bool includeMTProto,
           std::string& error);
// Remove rules matching this installation's name, group, marker and exact
// engine paths. Does not remove user-created rules, even for the same program.
bool remove(const std::wstring& installDirectory, std::string& error);
}
