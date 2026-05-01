#include <windows.h>
#include <winhttp.h>

#include <iostream>
#include <fstream>
#include <string>
#include <queue>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <unordered_map>
#include <atomic>
#include <chrono>
#include <ctime>
#include <cctype>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "winhttp.lib")

// =====================================================
// Native AMSI Bridge Agent - C++
// Version: Stable Bridge v2
//
// Role:
// 1. Receive ScanMessage from AMSI Provider through Named Pipe
// 2. Reduce benign PowerShell startup/module noise
// 3. Run fast local IOA rules
// 4. Terminate dangerous PowerShell process when confidence is high
// 5. Forward meaningful telemetry to Python EDR Agent through HTTP POST
// =====================================================

#define PIPE_NAME "\\\\.\\pipe\\EdrAmsiPipe"

// Python Agent endpoint
static const wchar_t* TELEMETRY_HOST = L"127.0.0.1";
static const INTERNET_PORT TELEMETRY_PORT = 9001;
static const wchar_t* TELEMETRY_PATH = L"/telemetry";

// Behavior switches
static const bool TERMINATE_ON_HIGH_CONFIDENCE = true;
static const bool ENABLE_PYTHON_FORWARD = true;

// false = only forward ALERT/TERMINATE to Python Agent
static const bool FORWARD_ALLOW_EVENTS = false;

// false = do not print benign ALLOW events to console/log
static const bool LOG_ALLOW_EVENTS = false;

static const size_t MAX_CACHE_SIZE = 5000;
static const int PYTHON_FAILURE_COOLDOWN_SECONDS = 10;
static const char* LOG_FILE = "edr_cpp_agent.log";

// ================= STRUCT SHARED WITH PROVIDER =================
#pragma pack(push, 1)
struct ScanMessage
{
    DWORD pid;
    DWORD parentPid;

    char process[260];
    char parentProcess[260];

    char sha256[65];
    char script[4096];
};
#pragma pack(pop)

// ================= GLOBALS =================
std::queue<ScanMessage> g_queue;
std::mutex g_queueMutex;
std::condition_variable g_queueCv;

std::unordered_map<std::string, std::string> g_verdictCache;
std::mutex g_cacheMutex;

std::mutex g_logMutex;
std::atomic<bool> g_running(true);
std::atomic<long long> g_nextPythonRetryEpoch(0);

// ================= UTILS =================
long long NowEpoch()
{
    return static_cast<long long>(std::time(nullptr));
}

std::string NowString()
{
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);

    tm localTime{};
    localtime_s(&localTime, &t);

    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &localTime);
    return std::string(buf);
}

void Log(const std::string& msg)
{
    std::lock_guard<std::mutex> lock(g_logMutex);

    std::string line = "[" + NowString() + "] " + msg;
    std::cout << line << std::endl;

    std::ofstream out(LOG_FILE, std::ios::app);
    if (out.is_open())
        out << line << std::endl;
}

std::string SafeCharArrayToString(const char* buffer, size_t maxLen)
{
    if (!buffer || maxLen == 0)
        return "";

    size_t len = 0;
    while (len < maxLen && buffer[len] != '\0')
        len++;

    return std::string(buffer, len);
}

std::string Normalize(const std::string& s)
{
    std::string out;
    out.reserve(s.size());

    for (unsigned char c : s)
    {
        if (!std::isspace(c))
            out += static_cast<char>(std::tolower(c));
    }

    return out;
}

std::string ToLowerCopy(const std::string& input)
{
    std::string out = input;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
        });
    return out;
}

std::string EscapeJson(const std::string& s)
{
    std::ostringstream out;

    for (unsigned char c : s)
    {
        switch (c)
        {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20)
            {
                char hex[8];
                sprintf_s(hex, sizeof(hex), "\\u%04x", c);
                out << hex;
            }
            else
            {
                out << c;
            }
        }
    }

    return out.str();
}

std::string TruncateForLog(const std::string& s, size_t maxLen = 700)
{
    if (s.size() <= maxLen)
        return s;

    return s.substr(0, maxLen) + " ...[truncated]";
}

// ================= NOISE FILTER =================
bool IsPowerShellModuleManifest(const std::string& script)
{
    std::string s = Normalize(script);

    return s.find("moduleversion") != std::string::npos &&
        s.find("cmdletstoexport") != std::string::npos &&
        s.find("guid") != std::string::npos &&
        (s.find("microsoftcorporation") != std::string::npos ||
            s.find("rootmodule") != std::string::npos ||
            s.find("nestedmodules") != std::string::npos ||
            s.find("author") != std::string::npos);
}

bool IsPSReadLineNoise(const std::string& script)
{
    std::string s = Normalize(script);

    return s.find("psconsolehostreadline") != std::string::npos ||
        s.find("microsoft.powershell.psconsolereadline") != std::string::npos ||
        s.find("psreadline") != std::string::npos;
}

bool ContainsSuspiciousKeyword(const std::string& script)
{
    std::string s = Normalize(script);

    return s.find("-encodedcommand") != std::string::npos ||
        s.find("-enc") != std::string::npos ||
        s.find("invoke-expression") != std::string::npos ||
        s.find("iex") != std::string::npos ||
        s.find("downloadstring") != std::string::npos ||
        s.find("downloadfile") != std::string::npos ||
        s.find("invoke-webrequest") != std::string::npos ||
        s.find("invoke-restmethod") != std::string::npos ||
        s.find("frombase64string") != std::string::npos ||
        s.find("mimikatz") != std::string::npos ||
        s.find("sekurlsa") != std::string::npos ||
        s.find("logonpasswords") != std::string::npos ||
        s.find("lsadump") != std::string::npos ||
        s.find("amsiutils") != std::string::npos ||
        s.find("amsiinitfailed") != std::string::npos ||
        s.find("disablerealtimemonitoring") != std::string::npos;
}

bool IsKnownBenignPowerShellNoise(const std::string& script)
{
    if (script.size() < 5)
        return true;

    if (IsPowerShellModuleManifest(script))
        return true;

    if (IsPSReadLineNoise(script) && !ContainsSuspiciousKeyword(script))
        return true;

    return false;
}

// ================= PROCESS CONTROL =================
bool TerminateProcessByPID(DWORD pid)
{
    if (pid == 0 || pid == GetCurrentProcessId())
        return false;

    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess)
    {
        Log("[ERROR] Cannot open process for terminate. PID=" + std::to_string(pid) +
            " Error=" + std::to_string(GetLastError()));
        return false;
    }

    BOOL ok = TerminateProcess(hProcess, 1);
    DWORD err = GetLastError();
    CloseHandle(hProcess);

    if (!ok)
    {
        Log("[ERROR] TerminateProcess failed. PID=" + std::to_string(pid) +
            " Error=" + std::to_string(err));
        return false;
    }

    Log("[ACTION] Terminated suspicious process. PID=" + std::to_string(pid));
    return true;
}

// ================= LOCAL IOA =================
std::string LocalAnalyze(const std::string& script)
{
    if (IsPowerShellModuleManifest(script))
        return "ALLOW";

    std::string s = Normalize(script);

    // High-confidence credential theft / post-exploitation indicators
    if (s.find("invoke-mimikatz") != std::string::npos ||
        s.find("mimikatz") != std::string::npos ||
        s.find("sekurlsa") != std::string::npos ||
        s.find("logonpasswords") != std::string::npos ||
        s.find("lsadump") != std::string::npos)
    {
        return "TERMINATE";
    }

    // Suspicious downloader / execution indicators
    if (s.find("downloadstring") != std::string::npos ||
        s.find("downloadfile") != std::string::npos ||
        s.find("invoke-webrequest") != std::string::npos ||
        s.find("invoke-restmethod") != std::string::npos ||
        s.find("new-objectnet.webclient") != std::string::npos)
    {
        return "ALERT";
    }

    // Obfuscation / dynamic execution indicators
    if (s.find("invoke-expression") != std::string::npos ||
        s.find("iex") != std::string::npos ||
        s.find("-encodedcommand") != std::string::npos ||
        s.find("-enc") != std::string::npos ||
        s.find("frombase64string") != std::string::npos)
    {
        return "ALERT";
    }

    // Defense evasion indicators
    if (s.find("amsiutils") != std::string::npos ||
        s.find("amsiinitfailed") != std::string::npos ||
        s.find("set-mppreference") != std::string::npos ||
        s.find("disablerealtimemonitoring") != std::string::npos)
    {
        return "ALERT";
    }

    return "ALLOW";
}

// ================= CACHE =================
bool CheckCache(const std::string& hash, std::string& verdict)
{
    if (hash.empty())
        return false;

    std::lock_guard<std::mutex> lock(g_cacheMutex);

    auto it = g_verdictCache.find(hash);
    if (it == g_verdictCache.end())
        return false;

    verdict = it->second;
    return true;
}

void UpdateCache(const std::string& hash, const std::string& verdict)
{
    if (hash.empty())
        return;

    std::lock_guard<std::mutex> lock(g_cacheMutex);

    if (g_verdictCache.size() > MAX_CACHE_SIZE)
        g_verdictCache.clear();

    g_verdictCache[hash] = verdict;
}

// ================= HTTP =================
bool IsPythonInCooldown()
{
    return NowEpoch() < g_nextPythonRetryEpoch.load();
}

void SetPythonCooldown()
{
    g_nextPythonRetryEpoch.store(NowEpoch() + PYTHON_FAILURE_COOLDOWN_SECONDS);
}

std::string BuildTelemetryJson(const ScanMessage& msg, const std::string& localVerdict)
{
    std::string process = SafeCharArrayToString(msg.process, sizeof(msg.process));
    std::string parentProcess = SafeCharArrayToString(msg.parentProcess, sizeof(msg.parentProcess));
    std::string sha256 = SafeCharArrayToString(msg.sha256, sizeof(msg.sha256));
    std::string script = SafeCharArrayToString(msg.script, sizeof(msg.script));

    std::string json = "{";
    json += "\"source\":\"amsi_cpp_bridge\",";
    json += "\"pid\":" + std::to_string(msg.pid) + ",";
    json += "\"ppid\":" + std::to_string(msg.parentPid) + ",";
    json += "\"process\":\"" + EscapeJson(process) + "\",";
    json += "\"parent_process\":\"" + EscapeJson(parentProcess) + "\",";
    json += "\"sha256\":\"" + EscapeJson(sha256) + "\",";
    json += "\"local_verdict\":\"" + EscapeJson(localVerdict) + "\",";
    json += "\"script\":\"" + EscapeJson(script) + "\"";
    json += "}";

    return json;
}

bool HttpPostJson(
    const wchar_t* host,
    INTERNET_PORT port,
    const wchar_t* path,
    const std::string& json,
    std::string& response)
{
    response.clear();

    HINTERNET hSession = WinHttpOpen(
        L"MiniEDR-CppAgent/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!hSession)
        return false;

    // Short timeout so Python offline does not freeze the queue.
    WinHttpSetTimeouts(hSession, 700, 700, 700, 1200);

    HINTERNET hConnect = WinHttpConnect(hSession, host, port, 0);
    if (!hConnect)
    {
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"POST",
        path,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);

    if (!hRequest)
    {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    const wchar_t* headers = L"Content-Type: application/json\r\n";

    BOOL ok = WinHttpSendRequest(
        hRequest,
        headers,
        (DWORD)-1L,
        (LPVOID)json.c_str(),
        (DWORD)json.size(),
        (DWORD)json.size(),
        0);

    if (!ok)
    {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    ok = WinHttpReceiveResponse(hRequest, NULL);
    if (!ok)
    {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD statusCode = 0;
    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &statusSize,
        WINHTTP_NO_HEADER_INDEX);

    char buffer[2048];
    DWORD bytesRead = 0;

    while (WinHttpReadData(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0)
    {
        response.append(buffer, bytesRead);
        bytesRead = 0;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return statusCode >= 200 && statusCode < 300;
}

std::string ParseVerdictFromResponse(const std::string& response)
{
    std::string r = Normalize(response);

    if (r.find("terminate") != std::string::npos)
        return "TERMINATE";

    if (r.find("alert") != std::string::npos)
        return "ALERT";

    return "ALLOW";
}

std::string ForwardToPythonAgent(const ScanMessage& msg, const std::string& localVerdict)
{
    if (!ENABLE_PYTHON_FORWARD)
        return "ALLOW";

    if (IsPythonInCooldown())
        return "ALLOW";

    std::string json = BuildTelemetryJson(msg, localVerdict);
    std::string response;

    bool ok = HttpPostJson(
        TELEMETRY_HOST,
        TELEMETRY_PORT,
        TELEMETRY_PATH,
        json,
        response);

    if (!ok)
    {
        Log("[WARN] Python Agent unavailable. Cooldown " +
            std::to_string(PYTHON_FAILURE_COOLDOWN_SECONDS) + "s.");
        SetPythonCooldown();
        return "ALLOW";
    }

    Log("[FORWARD] Sent telemetry to Python Agent. Response=" + response);
    return ParseVerdictFromResponse(response);
}

// ================= QUEUE =================
void EnqueueScan(const ScanMessage& msg)
{
    {
        std::lock_guard<std::mutex> lock(g_queueMutex);
        g_queue.push(msg);
    }

    g_queueCv.notify_one();
}

bool ShouldForwardByPolicy(const std::string& localVerdict)
{
    if (localVerdict == "ALERT" || localVerdict == "TERMINATE")
        return true;

    return FORWARD_ALLOW_EVENTS;
}

bool ShouldLogByPolicy(const std::string& localVerdict)
{
    if (localVerdict == "ALERT" || localVerdict == "TERMINATE")
        return true;

    return LOG_ALLOW_EVENTS;
}

void WorkerThread()
{
    while (g_running)
    {
        ScanMessage msg{};

        {
            std::unique_lock<std::mutex> lock(g_queueMutex);
            g_queueCv.wait(lock, [] {
                return !g_queue.empty() || !g_running.load();
                });

            if (!g_running && g_queue.empty())
                break;

            msg = g_queue.front();
            g_queue.pop();
        }

        std::string script = SafeCharArrayToString(msg.script, sizeof(msg.script));
        std::string hash = SafeCharArrayToString(msg.sha256, sizeof(msg.sha256));
        std::string process = SafeCharArrayToString(msg.process, sizeof(msg.process));
        std::string parentProcess = SafeCharArrayToString(msg.parentProcess, sizeof(msg.parentProcess));

        if (script.empty())
            continue;

        if (IsKnownBenignPowerShellNoise(script))
            continue;

        std::string localVerdict;

        if (CheckCache(hash, localVerdict))
        {
            if (ShouldLogByPolicy(localVerdict))
                Log("[CACHE] HIT hash=" + hash + " verdict=" + localVerdict);
        }
        else
        {
            localVerdict = LocalAnalyze(script);
            UpdateCache(hash, localVerdict);
        }

        bool shouldLog = ShouldLogByPolicy(localVerdict);
        bool shouldForward = ShouldForwardByPolicy(localVerdict);

        if (shouldLog)
        {
            Log("========================================");
            Log("[AMSI] PID=" + std::to_string(msg.pid) +
                " PPID=" + std::to_string(msg.parentPid) +
                " PROC=" + process +
                " PARENT=" + parentProcess);
            Log("[HASH] " + hash);
            Log("[LOCAL] verdict=" + localVerdict);
            Log("[SCRIPT] " + TruncateForLog(script));
        }

        bool alreadyTerminated = false;

        if (localVerdict == "TERMINATE" && TERMINATE_ON_HIGH_CONFIDENCE)
        {
            alreadyTerminated = TerminateProcessByPID(msg.pid);
        }

        if (shouldForward)
        {
            std::string remoteVerdict = ForwardToPythonAgent(msg, localVerdict);

            if (shouldLog)
                Log("[PYTHON_AGENT] verdict=" + remoteVerdict);

            if (remoteVerdict == "TERMINATE" && TERMINATE_ON_HIGH_CONFIDENCE && !alreadyTerminated)
            {
                TerminateProcessByPID(msg.pid);
            }
        }
    }
}

// ================= PIPE SERVER =================
HANDLE CreatePipeServer()
{
    return CreateNamedPipeA(
        PIPE_NAME,
        PIPE_ACCESS_INBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        sizeof(ScanMessage),
        sizeof(ScanMessage),
        0,
        NULL);
}

bool WaitForProvider(HANDLE pipe)
{
    BOOL connected = ConnectNamedPipe(pipe, NULL);

    if (connected)
        return true;

    DWORD err = GetLastError();

    // Provider connected before ConnectNamedPipe was called.
    if (err == ERROR_PIPE_CONNECTED)
        return true;

    Log("[ERROR] ConnectNamedPipe failed. Error=" + std::to_string(err));
    return false;
}

void PipeServerLoop()
{
    while (g_running)
    {
        HANDLE pipe = CreatePipeServer();

        if (pipe == INVALID_HANDLE_VALUE)
        {
            Log("[ERROR] CreateNamedPipe failed. Error=" + std::to_string(GetLastError()));
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }

        Log("[PIPE] Waiting for AMSI Provider connection...");

        if (!WaitForProvider(pipe))
        {
            CloseHandle(pipe);
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        Log("[PIPE] AMSI Provider connected.");

        while (g_running)
        {
            ScanMessage msg{};
            DWORD bytesRead = 0;

            BOOL ok = ReadFile(pipe, &msg, sizeof(msg), &bytesRead, NULL);

            if (!ok || bytesRead == 0)
            {
                DWORD err = GetLastError();
                Log("[PIPE] Provider disconnected or read failed. Error=" + std::to_string(err));
                break;
            }

            if (bytesRead != sizeof(ScanMessage))
            {
                Log("[WARN] Invalid ScanMessage size. BytesRead=" + std::to_string(bytesRead));
                continue;
            }

            EnqueueScan(msg);
        }

        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);

        Log("[PIPE] Restarting pipe server...");
    }
}

// ================= MAIN =================
int main()
{
    Log("[EDR] Native AMSI Bridge Agent started.");
    Log("[EDR] Pipe: " PIPE_NAME);
    Log("[EDR] Forward target: http://127.0.0.1:9001/telemetry");
    Log("[EDR] Policy: forward only ALERT/TERMINATE events; suppress benign PowerShell noise.");

    std::thread worker(WorkerThread);
    std::thread pipeServer(PipeServerLoop);

    worker.join();
    pipeServer.join();

    Log("[EDR] Agent stopped.");
    return 0;
}
