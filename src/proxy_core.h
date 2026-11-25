#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace proxy {
struct Config {
    unsigned short socksPort = 1080;
    unsigned short httpPort = 8080;
    std::string user;
    std::string password;
    std::string allowIp; // Empty = any IPv4; otherwise an exact source IPv4.
    bool enableSocks = true;
    bool enableHttp = true;
    bool enableSocksUdp = true;
    unsigned short udpPortMin = 20000;
    unsigned short udpPortMax = 20100;
    bool enableHttps = false;
    unsigned short httpsPort = 8443;
    bool enableSocksTls = false;
    unsigned short socksTlsPort = 1443;
    std::string tlsCertFile;
    std::string tlsKeyFile;
    std::string dnsServer; // Empty=system; otherwise explicit DNS upstream URI.
    bool enableDns = false;
    unsigned short dnsPort = 1053; // DNS listener binds only to 127.0.0.1.
    bool tlsUseChain = false;
    bool enableChainSocks = false;
    bool enableChainHttp = false;
    unsigned short chainSocksPort = 1081;
    unsigned short chainHttpPort = 8081;
    std::string upstreamType = "socks5";
    std::string upstreamHost;
    unsigned short upstreamPort = 1080;
    std::string upstreamUser;
    std::string upstreamPassword;
    std::string bindAddress = "0.0.0.0";
    unsigned maxConnections = 256;
    unsigned idleTimeoutSeconds = 1800;
    unsigned connectTimeoutSeconds = 15;
};
struct Stats {
    std::uint64_t active = 0, accepted = 0, rejected = 0, authFailed = 0;
    std::uint64_t socks = 0, http = 0, sent = 0, received = 0, connectFailed = 0;
    std::uint64_t connected = 0, authChallenges = 0, uptimeSeconds = 0;
    std::uint64_t chainSocks = 0, chainHttp = 0, chainConnected = 0, upstreamFailed = 0;
    bool metricsAvailable = false;
    std::uint64_t readyServices = 0, expectedServices = 0, failedServices = 0, handlerErrors = 0;
};
struct Event {
    std::uint64_t id = 0;
    std::string time;
    std::string level;
    std::string message;
};
bool networkInit(std::string& error);
void networkCleanup();
bool validate(const Config& c, std::string& error);
struct Backend;

// Windows GOST supervisor. Control methods and snapshots are called from the
// owning thread (desktop UI or service loop). The metrics worker never accesses
// the Server object itself.
class Server {
public:
    Server();
    ~Server();
    bool start(const Config& cfg, std::string& error);
    void stop();
    bool running() const;
    Stats stats() const;
    std::vector<Event> events(std::uint64_t afterId = 0) const;
    std::string lastError() const;
private:
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;
    std::unique_ptr<Backend> backend_;
};
}
