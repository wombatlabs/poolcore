#include "config.h"

#include "poolcore/bitcoinRPCClient.h"
#include "poolcore/ethereumRPCClient.h"

#include "poolcore/backend.h"
#include "poolcore/coinLibrary.h"
#include "poolcommon/utils.h"
#include "asyncio/asyncio.h"
#include "asyncio/socket.h"
#include "loguru.hpp"
#include <signal.h>

#if defined(OS_LINUX)
extern "C" int mallctl(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
#endif

static int interrupted = 0;
static int sigusrReceived = 0;
static void sigIntHandler(int) { interrupted = 1; }
static void sigUsrHandler(int) { sigusrReceived = 1; }

static void processSigUsr()
{
#if defined(OS_LINUX)
  mallctl("prof.dump", NULL, NULL, NULL, 0);
#endif
}

struct CContext {
  std::filesystem::path DatabasePath;
  std::unique_ptr<StatisticServer> Statistic;
};

std::filesystem::path userHomeDir()
{
  char homedir[512];
#ifdef _WIN32
  snprintf(homedir, sizeof(homedir), "%s%s", getenv("HOMEDRIVE"), getenv("HOMEPATH"));
#else
  snprintf(homedir, sizeof(homedir), "%s", getenv("HOME"));
#endif
  return homedir;
}

int main(int argc, char **argv)
{
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <configuration file>\n", argv[0]);
    return 1;
  }

  loguru::g_preamble_thread = true;
  loguru::g_preamble_file = true;
  loguru::g_flush_interval_ms = 100;
  loguru::g_stderr_verbosity = loguru::Verbosity_1;
  loguru::init(argc, argv);
  loguru::set_thread_name("main");

  CContext poolContext;

  initializeSocketSubsystem();
  asyncBase *monitorBase = createAsyncBase(amOSDefault);

  // Parse config
  FileDescriptor configFd;
  if (!configFd.open(argv[1])) {
    LOG_F(ERROR, "Can't open config file %s", argv[1]);
    return 1;
  }

  std::string configData;
  configData.resize(configFd.size());
  configFd.read(configData.data(), 0, configData.size());
  configFd.close();
  rapidjson::Document document;
  document.Parse<rapidjson::kParseCommentsFlag>(configData.c_str());
  if (document.HasParseError()) {
    LOG_F(ERROR, "Config file %s is not valid JSON", argv[1]);
    return 1;
  }

  CCoinConfig config;
  {
    std::string error;
    if (!config.load(document, error)) {
      LOG_F(ERROR, "Config file %s contains error", argv[1]);
      LOG_F(ERROR, "%s", error.c_str());
      return 1;
    }
  }

  {
    if (config.DbPath.starts_with("~/") || config.DbPath.starts_with("~\\"))
      poolContext.DatabasePath = userHomeDir() / (config.DbPath.data()+2);
    else
      poolContext.DatabasePath = config.DbPath;

    {
      char logFileName[64];
      auto t = time(nullptr);
      auto now = localtime(&t);
      snprintf(logFileName, sizeof(logFileName), "%s-statistic-%04u-%02u-%02u.log", config.Name.c_str(), now->tm_year + 1900, now->tm_mon + 1, now->tm_mday);
      std::filesystem::path logFilePath(poolContext.DatabasePath);
      loguru::add_file((poolContext.DatabasePath / logFileName).generic_string().c_str(), loguru::Append, loguru::Verbosity_1);
    }

    const char *coinName = config.Name.c_str();
    CCoinInfo coinInfo = CCoinLibrary::get(coinName);
    if (coinInfo.Name.empty()) {
      LOG_F(ERROR, "Unknown coin or algorithm: %s", coinName);
      return 1;
    }

    PoolBackendConfig algoConfig;
    algoConfig.dbPath = poolContext.DatabasePath / coinInfo.Name;
    poolContext.Statistic.reset(new StatisticServer(createAsyncBase(amOSDefault), algoConfig, coinInfo));
  }

  poolContext.Statistic->start();

  // Start monitor thread
  std::thread monitorThread([](asyncBase *base) {
    InitializeWorkerThread();
    loguru::set_thread_name("monitor");
    LOG_F(INFO, "monitor started tid=%u", GetGlobalThreadId());
    asyncLoop(base);
  }, monitorBase);

  // Handle CTRL+C (SIGINT)
  signal(SIGINT, sigIntHandler);
  signal(SIGTERM, sigIntHandler);
#ifndef WIN32
  signal(SIGUSR1, sigUsrHandler);
#endif

  std::thread sigIntThread([&monitorBase, &poolContext]() {
    loguru::set_thread_name("sigint_monitor");
    while (!interrupted) {
      if (sigusrReceived) {
        processSigUsr();
        sigusrReceived = 0;
      }
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    LOG_F(INFO, "Interrupted by user");
    // Stop backend
    poolContext.Statistic->stop();
    // Stop monitor thread
    postQuitOperation(monitorBase);
  });

  sigIntThread.detach();
  monitorThread.join();
  LOG_F(INFO, "poolfrondend stopped\n");
  return 0;
}
