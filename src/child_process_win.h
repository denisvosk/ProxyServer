#pragma once
#include <memory>
#include <string>
#include <vector>

// Windows-only child supervisor. Its callers provide a fixed, absolute path to
// a bundled executable. No shell, PATH lookup, service or firewall modifications.
namespace child_process {
class Process {
public:
    Process();
    ~Process();
    bool start(const std::wstring& absoluteExecutable,
               const std::vector<std::wstring>& arguments,
               const std::string& stdinConfiguration,
               std::string& error);
    void stop();
    void poll();
    bool running() const;
    std::string lastError() const;
    unsigned long lastExitCode() const;
private:
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
