#pragma once
#include <string>
#include "child_process_win.h"

// This is a Windows supervisor for the bundled audited mtg engine, not an
// implementation of the Telegram transport or its cryptography.
namespace mtproto {
struct Config {
    unsigned short listenPort = 443;
    std::string bindAddress = "0.0.0.0";
    std::string secret;     // ee + 16-byte random key + ASCII TLS hostname, hex.
    std::string publicHost; // Server address used in the Telegram connection link.
};
bool validate(const Config& config,std::string& error);
bool secretDomain(const std::string& secret,std::string& domain);
bool generateSecret(const std::string& domain,std::string& secret,std::string& error);
std::string buildTelegramLink(const Config& config);
class Controller {
public:
    bool start(const std::wstring& absoluteExePath,const Config& config,std::string& error);
    void stop();
    void poll();
    bool running() const;
    std::string lastError() const;
private:
    child_process::Process process_;
    std::string error_;
};
}
