#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <windows.h>
#include <process.h>
#include <atomic>
#include <algorithm>
#include <memory>
#include <string>
#include <vector>
#include "child_process_win.h"

namespace child_process {
namespace {
void closeHandle(HANDLE& handle) {
    if(handle && handle!=INVALID_HANDLE_VALUE) CloseHandle(handle);
    handle=nullptr;
}
struct Handle {
    HANDLE value=nullptr;
    ~Handle() { closeHandle(value); }
    HANDLE release() { HANDLE h=value; value=nullptr; return h; }
    Handle() {}
    Handle(const Handle&)=delete;
    Handle& operator=(const Handle&)=delete;
};
struct InputState {
    HANDLE pipe=nullptr;
    std::vector<char> bytes;
    std::atomic<bool> done{false};
    std::atomic<DWORD> error{ERROR_SUCCESS};
    ~InputState() {
        if(!bytes.empty()) SecureZeroMemory(bytes.data(),bytes.size());
        closeHandle(pipe);
    }
};
unsigned __stdcall writeConfiguration(void* argument) {
    std::unique_ptr<std::shared_ptr<InputState>> owner(
        static_cast<std::shared_ptr<InputState>*>(argument));
    const std::shared_ptr<InputState> state=*owner;
    std::size_t offset=0;
    while(offset<state->bytes.size()) {
        DWORD written=0;
        if(!WriteFile(state->pipe,state->bytes.data()+offset,
                      static_cast<DWORD>(state->bytes.size()-offset),&written,nullptr) || !written) {
            state->error=GetLastError();
            if(state->error==ERROR_SUCCESS) state->error=ERROR_WRITE_FAULT;
            break;
        }
        offset+=written;
    }
    if(!state->bytes.empty()) SecureZeroMemory(state->bytes.data(),state->bytes.size());
    state->bytes.clear();
    closeHandle(state->pipe); // EOF is required by engines reading stdin to completion.
    state->done=true;
    return 0;
}
bool absolutePath(const std::wstring& path) {
    if(path.size()<4 || path.find(L'\0')!=std::wstring::npos ||
       path.find_first_of(L"\r\n\"")!=std::wstring::npos) return false;
    const bool drive=((path[0]>=L'A'&&path[0]<=L'Z') || (path[0]>=L'a'&&path[0]<=L'z')) &&
                     path[1]==L':' && (path[2]==L'\\'||path[2]==L'/');
    const bool unc=path.size()>4 && path[0]==L'\\' && path[1]==L'\\';
    return drive||unc;
}
std::wstring quote(const std::wstring& input) {
    // CommandLineToArgvW / Microsoft CRT quoting rules, including trailing slashes.
    std::wstring result=L"\"";
    unsigned slashes=0;
    for(wchar_t ch:input) {
        if(ch==L'\\') { ++slashes; continue; }
        if(ch==L'\"') {
            result.append(slashes*2+1,L'\\'); result+=ch;
        } else {
            result.append(slashes,L'\\'); result+=ch;
        }
        slashes=0;
    }
    result.append(slashes*2,L'\\');
    result+=L'\"';
    return result;
}
std::string windowsError(const char* stage,DWORD code) {
    // Numeric errors are useful diagnostics and cannot contain child credentials.
    return std::string(stage)+u8" (код Windows "+std::to_string(code)+").";
}
bool controlledEnvironment(std::vector<wchar_t>& output) {
    LPWCH environment=GetEnvironmentStringsW();
    if(!environment) return false;
    struct FreeEnvironment { LPWCH value; ~FreeEnvironment(){FreeEnvironmentStringsW(value);} } guard{environment};
    for(const wchar_t* value=environment;*value;) {
        const wchar_t* end=value;
        while(*end) ++end;
        std::wstring name(value,end);
        for(wchar_t& c:name) if(c>=L'a'&&c<=L'z') c=static_cast<wchar_t>(c-L'a'+L'A');
        // Bundled engines must use only the validated stdin configuration.
        // Preserve OS/user environment except their documented override prefixes.
        if(name.compare(0,5,L"GOST_")!=0 && name.compare(0,4,L"MTG_")!=0) {
            output.insert(output.end(),value,end+1);
        }
        value=end+1;
    }
    output.push_back(L'\0');
    if(output.size()==1) output.push_back(L'\0');
    return true;
}
struct AttributeList {
    std::vector<unsigned char> storage;
    LPPROC_THREAD_ATTRIBUTE_LIST list=nullptr;
    ~AttributeList() { if(list) DeleteProcThreadAttributeList(list); }
    bool initialize(HANDLE* handles,SIZE_T handleCount) {
        SIZE_T size=0;
        InitializeProcThreadAttributeList(nullptr,1,0,&size);
        if(!size) return false;
        storage.resize(size);
        auto candidate=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        if(!InitializeProcThreadAttributeList(candidate,1,0,&size)) return false;
        list=candidate;
        return UpdateProcThreadAttribute(list,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                         handles,handleCount*sizeof(HANDLE),nullptr,nullptr)!=FALSE;
    }
};
}

struct Process::Impl {
    HANDLE process=nullptr,job=nullptr,output=nullptr,writer=nullptr;
    std::shared_ptr<InputState> input;
    ULONGLONG inputStarted=0;
    DWORD exitCode=0;
    std::string error;

    void discardOutput() {
        // Never retain or display raw child output: config parse errors in some
        // engines include the secret. A fixed drain budget keeps the UI responsive.
        if(!output) return;
        char buffer[4096];
        DWORD budget=65536;
        while(budget) {
            DWORD available=0;
            if(!PeekNamedPipe(output,nullptr,0,nullptr,&available,nullptr) || !available) break;
            DWORD want=(std::min)(available,(std::min)(budget,static_cast<DWORD>(sizeof(buffer))));
            DWORD got=0;
            if(!ReadFile(output,buffer,want,&got,nullptr) || !got) break;
            SecureZeroMemory(buffer,got);
            budget-=got;
        }
    }
    void closeProcess(bool terminate) {
        if(writer && input && !input->done) CancelSynchronousIo(writer);
        if(terminate && job) TerminateJobObject(job,0);
        // Closing the private job also kills descendants if the GUI exits/crashes.
        closeHandle(job);
        if(terminate && process) {
            TerminateProcess(process,0); // Only our owned process handle.
            WaitForSingleObject(process,200);
        }
        closeHandle(process);
        closeHandle(output);
        closeHandle(writer);
        input.reset(); // Writer holds its own state if it is still unwinding.
    }
};
Process::Process() : impl_(new Impl) {}
Process::~Process() { impl_->closeProcess(true); }

bool Process::start(const std::wstring& absoluteExecutable,
                    const std::vector<std::wstring>& arguments,
                    const std::string& stdinConfiguration,std::string& error) {
    poll();
    if(running()) { error=u8"Компонент уже запущен."; return false; }
    impl_->closeProcess(true);
    impl_->error.clear();
    impl_->exitCode=0;
    error.clear();
    auto fail=[&](const std::string& message)->bool {
        impl_->error=message; error=message; return false;
    };
    if(!absolutePath(absoluteExecutable)) return fail(u8"Для запуска компонента нужен полный путь к исполняемому файлу из комплекта.");
    DWORD attributes=GetFileAttributesW(absoluteExecutable.c_str());
    if(attributes==INVALID_FILE_ATTRIBUTES || (attributes&FILE_ATTRIBUTE_DIRECTORY))
        return fail(u8"Исполняемый файл компонента не найден. Распакуйте архив выпуска целиком.");
    if(stdinConfiguration.size()>65536) return fail(u8"Конфигурация компонента превышает ограничение 64 КиБ.");
    std::wstring command=quote(absoluteExecutable);
    for(const std::wstring& argument:arguments) {
        if(argument.find(L'\0')!=std::wstring::npos || argument.find_first_of(L"\r\n")!=std::wstring::npos)
            return fail(u8"Некорректный аргумент запуска компонента.");
        command+=L" "+quote(argument);
    }
    if(command.size()>30000) return fail(u8"Слишком длинная командная строка компонента.");
    std::vector<wchar_t> commandBuffer(command.begin(),command.end());
    commandBuffer.push_back(L'\0');
    const auto slash=absoluteExecutable.find_last_of(L"\\/");
    const std::wstring directory=absoluteExecutable.substr(0,slash+1);

    SECURITY_ATTRIBUTES security={sizeof(security),nullptr,TRUE};
    Handle inputRead,inputWrite,outputRead,outputWrite,job;
    if(!CreatePipe(&inputRead.value,&inputWrite.value,&security,65536) ||
       !SetHandleInformation(inputWrite.value,HANDLE_FLAG_INHERIT,0) ||
       !CreatePipe(&outputRead.value,&outputWrite.value,&security,65536) ||
       !SetHandleInformation(outputRead.value,HANDLE_FLAG_INHERIT,0))
        return fail(windowsError(u8"Не удалось создать каналы связи с компонентом",GetLastError()));
    job.value=CreateJobObjectW(nullptr,nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit={};
    limit.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if(!job.value || !SetInformationJobObject(job.value,JobObjectExtendedLimitInformation,&limit,sizeof(limit)))
        return fail(windowsError(u8"Не удалось создать объект управления компонентом",GetLastError()));

    HANDLE inherited[]={inputRead.value,outputWrite.value};
    AttributeList attributeList;
    if(!attributeList.initialize(inherited,2))
        return fail(windowsError(u8"Не удалось ограничить доступ компонента к дескрипторам приложения",GetLastError()));
    STARTUPINFOEXW startup={};
    startup.StartupInfo.cb=sizeof(startup);
    startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
    startup.StartupInfo.wShowWindow=SW_HIDE;
    startup.StartupInfo.hStdInput=inputRead.value;
    startup.StartupInfo.hStdOutput=outputWrite.value;
    startup.StartupInfo.hStdError=outputWrite.value;
    startup.lpAttributeList=attributeList.list;
    PROCESS_INFORMATION process={};
    std::vector<wchar_t> environment;
    if(!controlledEnvironment(environment)) return fail(windowsError(u8"Не удалось подготовить окружение компонента",GetLastError()));
    const DWORD flags=CREATE_NO_WINDOW|CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT|CREATE_UNICODE_ENVIRONMENT;
    if(!CreateProcessW(absoluteExecutable.c_str(),commandBuffer.data(),nullptr,nullptr,TRUE,
                       flags,environment.data(),directory.c_str(),&startup.StartupInfo,&process))
        return fail(windowsError(u8"Не удалось запустить компонент из комплекта",GetLastError()));
    Handle processHandle,threadHandle;
    processHandle.value=process.hProcess;
    threadHandle.value=process.hThread;
    if(!AssignProcessToJobObject(job.value,process.hProcess)) {
        const DWORD code=GetLastError();
        TerminateProcess(process.hProcess,0);
        return fail(windowsError(u8"Не удалось включить безопасное управление процессом компонента",code));
    }
    auto input=std::make_shared<InputState>();
    input->pipe=inputWrite.release();
    input->bytes.assign(stdinConfiguration.begin(),stdinConfiguration.end());
    // The writer owns its state. A stalled/misbehaving child cannot block the UI.
    auto writerArgument=new std::shared_ptr<InputState>(input);
    uintptr_t writer=_beginthreadex(nullptr,0,writeConfiguration,writerArgument,0,nullptr);
    if(!writer) {
        delete writerArgument;
        TerminateJobObject(job.value,0);
        return fail(u8"Не удалось запустить передачу конфигурации компоненту.");
    }
    Handle writerHandle;
    writerHandle.value=reinterpret_cast<HANDLE>(writer);
    if(ResumeThread(process.hThread)==static_cast<DWORD>(-1)) {
        const DWORD code=GetLastError();
        CancelSynchronousIo(writerHandle.value);
        TerminateJobObject(job.value,0);
        return fail(windowsError(u8"Не удалось продолжить запуск компонента",code));
    }
    closeHandle(inputRead.value);
    closeHandle(outputWrite.value);
    impl_->process=processHandle.release();
    impl_->job=job.release();
    impl_->output=outputRead.release();
    impl_->writer=writerHandle.release();
    impl_->input=input;
    impl_->inputStarted=GetTickCount64();
    return true;
}
void Process::stop() { impl_->closeProcess(true); }
void Process::poll() {
    if(!impl_->process) return;
    impl_->discardOutput();
    if(impl_->input) {
        if(impl_->input->done) {
            if(impl_->input->error!=ERROR_SUCCESS) {
                impl_->error=windowsError(u8"Не удалось передать конфигурацию компоненту",impl_->input->error);
                impl_->closeProcess(true);
                return;
            }
        } else if(GetTickCount64()-impl_->inputStarted>5000) {
            impl_->error=u8"Компонент не принял конфигурацию за 5 секунд.";
            impl_->closeProcess(true);
            return;
        }
    }
    const DWORD state=WaitForSingleObject(impl_->process,0);
    if(state==WAIT_FAILED) {
        impl_->error=windowsError(u8"Не удалось прочитать состояние компонента",GetLastError());
        impl_->closeProcess(true);
        return;
    }
    if(state==WAIT_OBJECT_0) {
        DWORD code=0;
        if(!GetExitCodeProcess(impl_->process,&code)) code=GetLastError();
        impl_->exitCode=code;
        impl_->error=u8"Компонент завершился (код "+std::to_string(code)+u8"). Проверьте порт, настройки и наличие компонентов из этого выпуска.";
        impl_->closeProcess(false);
    }
}
bool Process::running() const {
    if(!impl_->process) return false;
    return WaitForSingleObject(impl_->process,0)==WAIT_TIMEOUT;
}
std::string Process::lastError() const { return impl_->error; }
unsigned long Process::lastExitCode() const { return impl_->exitCode; }
}
