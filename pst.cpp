// For DIR, opendir()
#include <dirent.h>

// For getopt_long() option.
#include <getopt.h>

// Standard I/O streams.
#include <iostream>

// For read(), close(), sysconf()
#include <unistd.h>

// For open()
#include <fcntl.h>

// For ifstream
#include <fstream>

// For uptime
#include <sys/sysinfo.h>

// For process lists
#include <list>
#include <set>
#include <map>

// For strerror(), strtok(), strcmp(), strchr(), strstr()
#include <string.h>

// For ioctl()
#include <sys/ioctl.h>

#ifdef ANDROID

// For stringstream
#include <sstream>

#else

// For setw(), wstring_convert(), ostringstream, setprecision()
#include <iomanip>

#endif

// For codecvt_utf8_utf16
// Tree art unicode characters length measurement.
#include <codecvt>

// For device major / minor numbers.
#include <linux/kdev_t.h>

// For user name.
#include <pwd.h>

using namespace std;

/////////////////////////////////////////////////////////////////////////

#define VERSION "v0.2"

static int printErr(string msg)
{
    cerr << "ERR: " << msg << endl;
    return 1;
}

static int printErrCode(string msg)
{
    cerr << "ERR: " << msg << ": " << strerror(errno) << endl;
    return 1;
}

static int dupError(string str)
{
    return printErr("Duplicate " + str);
}

static bool isNumber(string num, string type, bool verbose)
{
    if (!num.length())
        return false;

    for (unsigned long i = 0; i < num.length(); i++)
    {
        if (!isdigit(num[i]))
        {
            if (verbose)
                printErr("Invalid " + type + ": " + num);
            return false;
        }
    }

    return true;
}

static int showUsage()
{
    cout << endl
         << "Usage:\n\tpst [options] [pid1 pid2 ...] [cmd1 cmd2 ...]\n"
         << endl
         << "Parses Linux procfs and prints process tree of all or matched processes.\n"
         << endl
         << "Options:\n"
         << "\t-o, --opt <opt,...>   Print only given columns\n"
         << "\t                      Columns: all, ppid, pid, tty, uid, ram*, swap*, cpu, age, io*, cmd\n"
         << "\t--kernel              Show kernel threads\n"
         << "\t--threads             Show process threads\n"
         << "\t--rss                 Show RSS RAM and SWAP instead of PSS\n"
         << "\t--cpu-time            Show CPU time instead of percentage\n"
         << "\t--total-io            Include I/O of dead threads and dead child processes\n"
         << "\t--no-tree             Print only given processes, not their child tree\n"
         << "\t--no-full             Match only the cmd part before first space, not the whole cmdline\n"
         << "\t--no-pid              Treat the numerical argument(s) as cmd, not pid\n"
         << "\t--no-name             Do not try to resolve uid to user name\n"
         << "\t--no-header           Do not print header\n"
         << "\t--no-trunc            Do not fit lines to terminal width\n"
         << "\t--ascii               Use ASCII characters for tree art\n"
         << "\t-v, --verbose         Print all errors\n"
         << "\t-V, --version         Show version\n"
         << "\t-h, --help            This help message\n"
         << endl
         << "\t* Required capabilities: CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH\n"
         << endl;

    return 1;
}

/////////////////////////////////////////////////////////////////////////

struct Proc
{
    bool failed = false;

    pid_t pid;

    // Thread only
    pid_t tid = 0;

    // stat
    int ppid = -1;
    string tty = "?";
    long cpuTime = -1; // millisec
    long age = -1;     // millisec

    // status
    uid_t uid = -1;

    // smaps
    long pss = -1;     // bytes
    long swapPss = -1; // bytes

    // cmdline (or comm for threads and kernel threads)
    string cmdline = "-";

    // io
    long long readIO = -1;  // bytes
    long long writeIO = -1; // bytes
};

static map<pid_t, Proc> procMap;
static map<pid_t, list<Proc>> childMap;
static map<pid_t, string> errMap;

static int col_wid_ppid = 8;
static int col_wid_pid = 8;
static int col_wid_tid = 8;
static int col_wid_tty = 8;
static int col_wid_uid = 10;
static int col_wid_ram = 10;
static int col_wid_swap = 10;
static int col_wid_cpu = 8;
static int col_wid_age = 8;
static int col_wid_rio = 10;
static int col_wid_wio = 10;

static bool show_col_ppid = true;
static bool show_col_pid = true;
static bool show_col_tty = false;
static bool show_col_uid = true;
static bool show_col_ram = false;
static bool show_col_swap = false;
static bool show_col_cpu = false;
static bool show_col_age = false;
static bool show_col_rio = false;
static bool show_col_wio = false;
static bool show_col_cmd = true;

static bool skipKernel = true;
static bool skipThreads = true;
static bool rssMem = false;
static bool cpuTime = false;
static bool totalIo = false;
static bool noTree = false;
static bool exeOnly = false;
static bool noPid = false;
static bool noName = false;
static bool noHeader = false;
static bool noTrunc = false;
static bool artASCII = false;
static bool verbose = false;

static bool hasMatchArgs;

static int TERM_COLS;

static string SMAPS_MATCH_RAM;
static string SMAPS_MATCH_SWAP;

static string ART_UP_RIGHT;
static string ART_VERT_RIGHT;
static string ART_HORIZ;
static string ART_DOWN_HORIZ;
static string ART_HORIZ_LEFT;
static string ART_VERT;

static int parseProcOpts(char *procOpts)
{
    if (procOpts == nullptr)
        return 0;

    show_col_ppid = show_col_pid = show_col_uid = show_col_cmd = false;

    char *token = strtok(procOpts, ",");
    while (token)
    {
        if (!strcmp(token, "all"))
            show_col_ppid = show_col_pid = show_col_tty = show_col_uid = show_col_ram = show_col_swap =
                show_col_cpu = show_col_age = show_col_rio = show_col_wio = show_col_cmd = true;
        else if (!strcmp(token, "ppid"))
            show_col_ppid = true;
        else if (!strcmp(token, "pid"))
            show_col_pid = true;
        else if (!strcmp(token, "tty"))
            show_col_tty = true;
        else if (!strcmp(token, "uid"))
            show_col_uid = true;
        else if (!strcmp(token, "ram"))
            show_col_ram = true;
        else if (!strcmp(token, "swap"))
            show_col_swap = true;
        else if (!strcmp(token, "cpu"))
            show_col_cpu = true;
        else if (!strcmp(token, "age"))
            show_col_age = true;
        else if (!strcmp(token, "io"))
            show_col_rio = show_col_wio = true;
        else if (!strcmp(token, "cmd"))
            show_col_cmd = true;
        else
            return printErr("Bad argument with --opt: " + (string)token);

        token = strtok(0, ",");
    }

    if (!show_col_ppid && !show_col_pid && !show_col_tty && !show_col_uid && !show_col_ram && !show_col_swap && !show_col_cpu && !show_col_age && !show_col_rio && !show_col_wio && !show_col_cmd)
        return printErr("No column selected");

    return 0;
}

static int parseOpts(int argc, char **argv)
{
    char *opts = nullptr;

    enum
    {
        OPT_OPT = 'o',
        OPT_INC_KERNEL = '0',
        OPT_INC_THREADS = '1',
        OPT_RSS = '2',
        OPT_CPU_TIME = '3',
        OPT_TOT_IO = '4',
        OPT_NO_TREE = '5',
        OPT_NO_FULL = '6',
        OPT_NO_PID = '7',
        OPT_NO_NAME = '8',
        OPT_NO_HDR = '9',
        OPT_NO_TRUNC = 't',
        OPT_ASCII = 'a',
        OPT_VERBOSE = 'v',
        OPT_VERSION = 'V',
        OPT_HELP = 'h'
    };

    // https://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Options.html
    // 'struct' qualifier is optional in C++
    const option longOpts[] = {{"opt", required_argument, nullptr, OPT_OPT},
                               {"kernel", no_argument, nullptr, OPT_INC_KERNEL},
                               {"threads", no_argument, nullptr, OPT_INC_THREADS},
                               {"rss", no_argument, nullptr, OPT_RSS},
                               {"cpu-time", no_argument, nullptr, OPT_CPU_TIME},
                               {"total-io", no_argument, nullptr, OPT_TOT_IO},
                               {"no-tree", no_argument, nullptr, OPT_NO_TREE},
                               {"no-full", no_argument, nullptr, OPT_NO_FULL},
                               {"no-pid", no_argument, nullptr, OPT_NO_PID},
                               {"no-name", no_argument, nullptr, OPT_NO_NAME},
                               {"no-header", no_argument, nullptr, OPT_NO_HDR},
                               {"no-trunc", no_argument, nullptr, OPT_NO_TRUNC},
                               {"ascii", no_argument, nullptr, OPT_ASCII},
                               {"verbose", no_argument, nullptr, OPT_VERBOSE},
                               {"version", no_argument, nullptr, OPT_VERSION},
                               {"help", no_argument, nullptr, OPT_HELP},
                               {nullptr, no_argument, nullptr, 0}};

    int opt;

    while ((opt = getopt_long(argc, argv, "o:vVh", longOpts, nullptr)) != -1)
    {
        switch (opt)
        {
        case OPT_OPT:
            if (opts != nullptr)
                return dupError("opt");
            opts = optarg;
            break;
        case OPT_INC_KERNEL:
            skipKernel = false;
            break;
        case OPT_INC_THREADS:
            skipThreads = false;
            break;
        case OPT_RSS:
            rssMem = true;
            break;
        case OPT_CPU_TIME:
            cpuTime = true;
            break;
        case OPT_TOT_IO:
            totalIo = true;
            break;
        case OPT_NO_TREE:
            noTree = true;
            break;
        case OPT_NO_FULL:
            exeOnly = true;
            break;
        case OPT_NO_PID:
            noPid = true;
            break;
        case OPT_NO_NAME:
            noName = true;
            break;
        case OPT_NO_HDR:
            noHeader = true;
            break;
        case OPT_NO_TRUNC:
            noTrunc = true;
            break;
        case OPT_ASCII:
            artASCII = true;
            break;
        case OPT_VERBOSE:
            verbose = true;
            break;
        case OPT_VERSION:
            cout << "pst " << VERSION << endl;
            exit(EXIT_SUCCESS);
        case OPT_HELP:
            showUsage();
            exit(EXIT_SUCCESS);
        case '?':
            return showUsage();
        }
    }

    hasMatchArgs = argc != optind;

    if (noTree && !hasMatchArgs)
        return printErr("--no-tree requires pid or cmd argument to match");

    if (exeOnly && !hasMatchArgs)
        return printErr("--no-full requires pid or cmd argument to match");

    if (noPid && !hasMatchArgs)
        return printErr("--no-pid requires pid or cmd argument to match");

    if (parseProcOpts(opts))
        return 1;

    if (rssMem && !show_col_ram && !show_col_swap)
        return printErr("--rss requires 'ram' or 'swap' column");

    if (cpuTime && !show_col_cpu)
        return printErr("--cpu-time requires 'cpu' column");

    if (totalIo && !show_col_rio && !show_col_wio)
        return printErr("--total-io requires 'io' column");

    if (noName && !show_col_uid)
        return printErr("--no-name requires 'uid' column");

    return 0;
}

static void initVars()
{
    struct winsize ws;
    TERM_COLS = ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) ? -1 : ws.ws_col;

    if (!artASCII && !isatty(STDOUT_FILENO))
        artASCII = true;

    SMAPS_MATCH_RAM = rssMem ? "Rss:" : "Pss:";
    SMAPS_MATCH_SWAP = rssMem ? "Swap:" : "SwapPss:";

    ART_UP_RIGHT = artASCII ? "`" : "\u2570";
    ART_VERT_RIGHT = artASCII ? "|" : "\u251c";
    ART_HORIZ = artASCII ? "-" : "\u2500";
    ART_DOWN_HORIZ = artASCII ? "-" : "\u252c";
    ART_HORIZ_LEFT = artASCII ? "-" : "\u2574";
    ART_VERT = artASCII ? "|" : "\u2502";
}

/////////////////////////////////////////////////////////////////////////

// https://github.com/htop-dev/htop/blob/3.0.5/linux/LinuxProcessList.c#L1252
// https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-11.0.0_r1/core/jni/android_util_Process.cpp#708
static int parseProcTree(string path, auto cb, bool printErr = true)
{
    DIR *dir = opendir(path.c_str());

    if (!dir)
        return printErr ? printErrCode("Failed to read " + path) : 1;

    const struct dirent *entry;

    int err = 0;

    while ((entry = readdir(dir)))
    {
        // Ignore non-directories
        if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN)
            continue;

        const char *name = entry->d_name;

        // Skip non-number directories
        if (name[0] < '0' || name[0] > '9')
            continue;

        pid_t pid = stoi(name);

        if (pid > 0 && !cb(pid))
        {
            err = 1;
            break;
        }
    }

    closedir(dir);
    return err;
}

static int handleProcReadError(string path, Proc &proc)
{
    if (errno != ENOENT)
    {
        if (verbose)
            printErrCode("Failed to read " + path);
        else if (!proc.tid)
            errMap.insert({proc.pid, "Failed to read " + path + ": " + strerror(errno)});
    }

    proc.failed = true;
    return 1;
}

static int getLines(string path, Proc &proc, auto cb)
{
    errno = 0;

    ifstream file;
    file.open(path);

    try
    {
        if (!file.good())
            return handleProcReadError(path, proc);
    }
    catch (const std::ios::failure &)
    {
        return handleProcReadError(path, proc);
    }

    string line, field;

    while (getline(file, line))
    {
        if (!cb(line))
            break;
    }

    file.close();
    return 0;
}

// For uptime
static struct sysinfo sInfo;

// For cpu time and start time
static int SC_CLK_TCK;

static void parseStat(Proc &proc)
{
    string path = "/proc/" + to_string(proc.pid) + (proc.tid ? "/task/" + to_string(proc.tid) : "") + "/stat";
    int fd = open(path.c_str(), O_RDONLY);

    if (fd < 0)
    {
        handleProcReadError(path, proc);
        return;
    }

    char buf[4096];

    int len = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (len < 0)
    {
        handleProcReadError(path, proc);
        return;
    }

    buf[len] = '\0'; // Ignore buffer contents beyond this position

    // Jump to the end of 2nd field (comm)
    char *del = strrchr(buf, ')');

    // Jump to the start of 4th field (ppid)
    for (int i = 1; i <= 2; i++)
    {
        del = strchr(del, ' ');
        del++;
    }

    proc.ppid = stoi(del);

    if (skipKernel && proc.ppid == 2)
        return;

    // 7th field (tty_nr)
    for (int i = 1; i <= 3; i++)
    {
        del = strchr(del, ' ');
        del++;
    }

    if (show_col_tty)
    {
        int dev = stoi(del);
        if (dev != 0)
        {
            int maj = MAJOR(dev);
            int min = MINOR(dev);

            // https://gitlab.com/procps-ng/procps/-/blob/v4.0.1/library/devname.c#L323
            if (maj == 4)
                proc.tty = "tty" + to_string(min);
            else if (maj == 136)
                proc.tty = "pts/" + to_string(min);
            else
            {
                // May also read from /proc/devices
                FILE *file = fopen(("/sys/dev/char/" + to_string(maj) + ":" + to_string(min) + "/uevent").c_str(), "r");
                char buf1[256];

                int count;
                bool found = false;

                if (file && (count = fread(buf1, 1, sizeof(buf1) - 1, file)) > 0)
                {
                    buf1[count] = '\0';

                    char *ptr = strstr(buf1, "DEVNAME=");
                    if (ptr)
                    {
                        char *buf2 = ptr + 8;
                        ptr = strchr(buf2, '\n');
                        if (ptr)
                        {
                            *ptr = '\0';
                            proc.tty = buf2;
                            found = true;
                        }
                    }
                }
                if (!found)
                    proc.tty = to_string(maj) + "." + to_string(min);
            }
        }
    }

    if (!show_col_age && !show_col_cpu)
        return;

    // 14th field (utime)
    for (int i = 1; i <= 7; i++)
    {
        del = strchr(del, ' ');
        del++;
    }

    long utime = 0;

    if (show_col_cpu)
        utime = stoll(del);

    // 15th field (stime)
    del = strchr(del, ' ');
    del++;

    if (show_col_cpu)
        proc.cpuTime = 1000 * (utime + stoll(del)) / SC_CLK_TCK;

    // 22nd field (starttime)
    for (int i = 1; i <= 7; i++)
    {
        del = strchr(del, ' ');
        del++;
    }

    if (sysinfo(&sInfo))
    {
        printErrCode("Failed to get sysinfo");
        proc.failed = true;
    }
    else
        proc.age = 1000 * sInfo.uptime - 1000 * stoll(del) / SC_CLK_TCK;
}

static void parseStatus(Proc &proc)
{
    if (proc.failed || !show_col_uid)
        return;

    string field;

    auto cb = [&](string line) -> bool
    {
        stringstream ss(line);
        ss >> field;

        if (field == "Uid:")
        {
            ss >> proc.uid >> proc.uid;
            return false;
        }

        return true;
    };

    getLines("/proc/" + to_string(proc.pid) + (proc.tid ? "/task/" + to_string(proc.tid) : "") + "/status", proc, cb);
}

static string removeBlanks(string &str)
{
    if (!str.empty())
    {
        string &s = str;
        size_t p = 0;
        size_t n = string::npos;

        while ((p = s.find('\0')) != n || (p = s.find('\t')) != n)
            str[p] = ' ';

        while ((p = str.find("  ")) != n)
            str.replace(p, 2, " ");

        if (str[0] == ' ')
            str.replace(0, 1, "");

        if (str.back() == ' ')
            str.replace(str.length() - 1, 1, "");
    }
    return str;
}

static int readLineInFile(string path, string &line)
{
    ifstream file;
    file.open(path);

    try
    {
        if (!file.good())
            return 1;
    }
    catch (const std::ios::failure &)
    {
        return 1;
    }

    getline(file, line);
    file.close();
    return 0;
}

static void getCmdline(Proc &proc)
{
    if (proc.failed || !show_col_cmd)
        return;

    string path;

    if (proc.pid == 2 || proc.ppid == 2 || proc.tid)
        // "cmdline" is always empty for kernel threads.
        path = "comm";
    else
        path = "cmdline";

    path = "/proc/" + to_string(proc.pid) + (proc.tid ? "/task/" + to_string(proc.tid) : "") + "/" + path;
    string line;

    if (readLineInFile(path, line))
        handleProcReadError(path, proc);
    else
        proc.cmdline = removeBlanks(line);
}

static void getPss(Proc &proc)
{
    if (proc.failed || proc.pid == 2 || proc.ppid == 2 || (!show_col_ram && !show_col_swap) || proc.tid)
        return;

    string path = "/proc/" + to_string(proc.pid) + "/smaps_rollup";
    if (access(path.c_str(), F_OK) == -1)
        path = "/proc/" + to_string(proc.pid) + "/smaps";

    string field;
    long num, pss = 0, swapPss = 0;

    auto cb = [&](string line) -> bool
    {
        stringstream ss(line);
        ss >> field;

        if (field == SMAPS_MATCH_RAM)
        {
            ss >> num;
            pss += num;
        }
        else if (field == SMAPS_MATCH_SWAP)
        {
            ss >> num;
            swapPss += num;
        }

        return true;
    };

    if (!getLines(path, proc, cb))
    {
        proc.pss = pss * 1024;
        proc.swapPss = swapPss * 1024;
    }
}

static void getIo(Proc &proc)
{
    if (proc.failed || (!show_col_rio && !show_col_wio))
        return;

    string field;
    long long num, readIO = 0, writeIO = 0;

    auto cb = [&](string line) -> bool
    {
        stringstream ss(line);
        ss >> field;

        if (field == "read_bytes:")
        {
            ss >> num;
            readIO += num;
        }
        else if (field == "write_bytes:")
        {
            ss >> num;
            writeIO += num;
        }

        return true;
    };

    int err;

    if (totalIo || proc.tid)
        err = getLines("/proc/" + to_string(proc.pid) + (proc.tid ? "/task/" + to_string(proc.tid) : "") + "/io", proc, cb);
    else
    {
        err = 0;

        string taskDir = "/proc/" + to_string(proc.pid) + "/task/";
        auto tidCb = [&](pid_t tid) -> bool
        {
            err = getLines(taskDir + to_string(tid) + "/io", proc, cb) || err;
            return true;
        };

        if (parseProcTree(taskDir, tidCb, false))
            err = handleProcReadError(taskDir, proc);
    }

    if (!err)
    {
        proc.readIO = readIO;
        proc.writeIO = writeIO;
    }
}

static map<uid_t, string> userNames;

static string getUserName(uid_t uid)
{
    if (noName)
        return to_string(uid);

    if (userNames.find(uid) != userNames.end())
        return userNames[uid];

    string user;

    struct passwd *pw = getpwuid(uid);
    if (pw)
    {
        user = pw->pw_name;
        if ((int)user.length() > col_wid_uid - 2)
            user = user.substr(0, col_wid_uid - 3) + "+";
    }
    else
        user = to_string(uid);

    userNames.insert({uid, user});

    return user;
}

static set<pid_t> skippedKernelProc;

static int createProc(Proc &proc, pid_t pid, pid_t tid = 0)
{
    if (skipKernel && pid == 2)
    {
        skippedKernelProc.insert(pid);
        return 0;
    }

    proc.pid = pid;
    proc.tid = tid;

    parseStat(proc);
    if (!tid && skipKernel && proc.ppid == 2)
    {
        skippedKernelProc.insert(pid);
        return 0;
    }

    parseStatus(proc);
    getCmdline(proc);
    if (!tid)
        getPss(proc);
    getIo(proc);

    if (tid || proc.failed)
        return 0;

    if (!procMap.insert({proc.pid, proc}).second)
        return printErr("Failed to build proc map");

    list<Proc> children;

    if (childMap.find(proc.ppid) != childMap.end())
        children = childMap[proc.ppid];

    children.push_back(proc);
    childMap[proc.ppid] = children;

    return 0;
}

static void matchCmd(string str, set<pid_t> &pidList)
{
    pid_t myPid = getpid();

    bool matched = false;
    for (auto pair : procMap)
    {
        Proc proc = pair.second;

        if (proc.pid == myPid)
            continue;

        char *cmd = (char *)proc.cmdline.c_str();

        if (exeOnly)
        {
            char *p = strchr(cmd, ' ');
            if (p)
                *p = '\0';
        }

        if (strstr(cmd, str.c_str()))
        {
            matched = true;
            pidList.insert(proc.pid);
        }
    }

    if (verbose && !matched)
        printErr((string) "No match for process name: " + str);
}

static int parseArgs(char **args, int size, set<pid_t> &pidList)
{
    for (int i = 0; i < size; i++)
    {
        string str = args[i];

        if (!noPid && isNumber(str, "pid", false))
        {
            pid_t pid = stoi(str);
            if (procMap.find(pid) != procMap.end())
                pidList.insert(pid);
            else if (verbose)
            {
                if (skipKernel && skippedKernelProc.find(pid) != skippedKernelProc.end())
                    printErr((string) "Ignoring pid " + str);
                else if (errMap.find(pid) != errMap.end())
                    printErr((string) "Pid " + str + ": " + errMap[pid]);
                else
                    printErr((string) "Pid " + str + " not found");
            }
        }
        else
            matchCmd(str, pidList);
    }

    if (pidList.empty())
        return verbose ? 1 : printErr("Nothing matched");

    return 0;
}

static auto constexpr MB = 1000000.0;
static auto constexpr GB = 1000000000.0;

static string toReadableSize(long bytes)
{
    if (bytes < MB)
        return to_string(bytes / 1000) + " KB";

    ostringstream oss;

    if (bytes < GB)
        oss << fixed << setprecision(1) << bytes / MB << " MB";
    else
        oss << fixed << setprecision(1) << bytes / GB << " GB";

    return oss.str();
}

static string toReadableTime(long sec)
{
    int d, h, m;

    d = sec / (60 * 60 * 24);
    sec -= d * (60 * 60 * 24);

    h = sec / (60 * 60);
    sec -= h * (60 * 60);

    m = sec / 60;
    sec -= m * 60;

    if (d > 0)
        return to_string(d) + "d" + (h > 0 ? to_string(h) + "h" : "");

    if (h > 0)
        return to_string(h) + "h" + (m > 0 ? to_string(m) + "m" : "");

    if (m > 0)
        return to_string(m) + "m" + (sec > 0 ? to_string(sec) + "s" : "");

    return to_string(sec) + "s";
}

static string toPercentage(long dividend, long divisor)
{
    ostringstream oss;
    oss << fixed << setprecision(2) << 100 * dividend / (float)divisor << "%";
    return oss.str();
}

static wstring_convert<std::codecvt_utf8_utf16<wchar_t>> WCHAR_CONVERTER;

static void printProc(Proc proc, string prefix)
{
    ostringstream line;

    if (show_col_ppid)
        line << setw(col_wid_ppid) << proc.ppid;
    if (show_col_pid)
        line << setw(col_wid_pid) << proc.pid;
    if (!skipThreads)
        line << setw(col_wid_tid) << (proc.tid ? to_string(proc.tid) : "-");
    if (show_col_tty)
        line << setw(col_wid_tty) << (proc.tid ? "-" : proc.tty);
    if (show_col_uid)
        line << "  " << setw(col_wid_uid) << left << getUserName(proc.uid) << right;
    if (show_col_ram)
        line << setw(col_wid_ram) << (proc.tid ? "-" : (proc.pid == 2 || proc.ppid == 2 ? "-" : toReadableSize(proc.pss)));
    if (show_col_swap)
        line << setw(col_wid_swap) << (proc.tid ? "-" : (proc.pid == 2 || proc.ppid == 2 ? "-" : toReadableSize(proc.swapPss)));
    if (show_col_cpu)
        line << setw(col_wid_cpu) << (cpuTime ? toReadableTime(proc.cpuTime / 1000) : toPercentage(proc.cpuTime, proc.age));
    if (show_col_age)
        line << setw(col_wid_age) << toReadableTime(proc.age / 1000);
    if (show_col_rio)
        line << setw(col_wid_rio) << toReadableSize(proc.readIO);
    if (show_col_wio)
        line << setw(col_wid_wio) << toReadableSize(proc.writeIO);
    if (show_col_cmd)
        line << "  " << prefix << proc.cmdline;

    string s = line.str();

    if (noTrunc)
        cout << s << endl;
    else
    {
        wstring ws = WCHAR_CONVERTER.from_bytes(s);
        cout << s.substr(0, TERM_COLS + s.length() - ws.length()) << endl;
    }
}

struct TreeEntry
{
    unsigned int siblingCount, curSibling;
};

static void printPidTree(pid_t pid, list<TreeEntry> tree)
{
    // PID 0 is not a real parent. Or in case if PIDs from procMap
    // are already consumed being child of a previously printed PID.
    bool hasParent = procMap.find(pid) != procMap.end();

    bool hasChildren = !noTree && childMap.find(pid) != childMap.end();

    if (hasParent)
    {
        string prefix = "", tidPrefix = "";
        int iter = 1, size = tree.size();
        bool last;

        for (struct TreeEntry te : tree)
        {
            last = te.siblingCount == te.curSibling;
            if (iter++ == size)
            {
                prefix += last ? ART_UP_RIGHT : ART_VERT_RIGHT;
                prefix += ART_HORIZ;
                prefix += hasChildren ? ART_DOWN_HORIZ : ART_HORIZ;
                prefix += ART_HORIZ_LEFT;

                tidPrefix += last ? " " : ART_VERT;
                tidPrefix += " ";
                tidPrefix += hasChildren ? ART_VERT : " ";
                tidPrefix += " ";
            }
            else
            {
                prefix += (last ? " " : ART_VERT) + " ";
                tidPrefix += (last ? " " : ART_VERT) + " ";
            }
        }

        Proc proc = procMap[pid];
        printProc(proc, prefix);

        procMap.erase(pid);

        if (!skipThreads && pid != 2 && proc.ppid != 2)
        {
            list<Proc> threads;
            auto cb = [&](pid_t tid) -> bool
            {
                Proc proc;
                createProc(proc, pid, tid);

                if (!proc.failed)
                    threads.push_back(proc);

                return true;
            };

            parseProcTree("/proc/" + to_string(pid) + "/task", cb);

            int i = 0, size = threads.size();
            string threadPrefix;

            for (Proc proc : threads)
            {
                threadPrefix = tidPrefix;

                if (++i == size)
                    threadPrefix += hasChildren && tree.empty() ? ART_VERT_RIGHT : ART_UP_RIGHT;
                else
                    threadPrefix += ART_VERT_RIGHT;

                threadPrefix += ART_HORIZ_LEFT;

                printProc(proc, threadPrefix);
            }
        }
    }

    if (!hasChildren)
        return;

    auto children = childMap[pid];
    childMap.erase(pid);

    if (hasParent)
        tree.push_back({.siblingCount = (unsigned int)children.size(), .curSibling = 1});

    for (Proc proc : children)
    {
        printPidTree(proc.pid, tree);
        if (hasParent)
            tree.back().curSibling++;
    }
}

static void printHeader()
{
    if (noHeader)
        return;

    auto printHdr = [](bool show, string title, int width, bool leftAlign)
    {
        if (show)
        {
            if (leftAlign)
                cout << "  " << setw(width) << left << title << right;
            else
                cout << setw(width) << title;
        }
    };

    printHdr(show_col_ppid, "PPID", col_wid_ppid, false);
    printHdr(show_col_pid, "PID", col_wid_pid, false);
    printHdr(!skipThreads, "TID", col_wid_tid, false);
    printHdr(show_col_tty, "TTY", col_wid_tty, false);
    printHdr(show_col_uid, "UID", col_wid_uid, true);
    printHdr(show_col_ram, "RAM", col_wid_ram, false);
    printHdr(show_col_swap, "SWAP", col_wid_swap, false);
    printHdr(show_col_cpu, "CPU", col_wid_cpu, false);
    printHdr(show_col_age, "AGE", col_wid_age, false);
    printHdr(show_col_rio, "IO-R", col_wid_rio, false);
    printHdr(show_col_wio, "IO-W", col_wid_wio, false);

    if (show_col_cmd)
        cout << "  COMMAND";

    cout << endl;
}

/////////////////////////////////////////////////////////////////////////

int main(int argc, char **argv)
{
    if (argc > 1 && parseOpts(argc, argv))
        return 1;

    if ((SC_CLK_TCK = sysconf(_SC_CLK_TCK)) == -1)
        return printErrCode("Failed to get SC_CLK_TCK");

    initVars();

    bool origVerbose = verbose;
    bool origShowCmd = show_col_cmd;

    if (hasMatchArgs)
    {
        // We'll only print errors for given args.
        verbose = false;

        // Required to match given args (which can be cmdline).
        show_col_cmd = true;
    }

    set<pid_t> pidList;

    if (parseProcTree("/proc", [](pid_t pid) -> bool
                      {
                        Proc proc;
                        return !createProc(proc, pid); }))
        return 1;

    verbose = origVerbose;
    show_col_cmd = origShowCmd;

    if (hasMatchArgs && parseArgs(argv + optind, argc - optind, pidList))
        return 1;

    // If failed to get any PID from /proc due to e.g. permission denied.
    if (childMap.empty())
        return printErr("Failed to get any pid");

    printHeader();

    // If no args were provided.
    if (pidList.empty())
    {
        // Not hard-coding PID 0 or 1 as root process of the tree b/c it
        // might not have been created due to e.g. permission denied.
        for (auto pair : childMap)
            pidList.insert(pair.first);
    }

    for (pid_t pid : pidList)
        printPidTree(pid, {});

    if (!errMap.empty())
        return verbose ? 1 : printErr("Failed to get " + to_string(errMap.size()) + " pids");

    return 0;
}
