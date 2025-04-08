#include "config.h"
#include <stdio.h>

#include "poolinstances/fabric.h"
#include "poolinstances/stratum.h"
#include "poolcore/thread.h"
#include "poolcommon/file.h"
#include "asyncio/asyncio.h"
#include "asyncio/socket.h"
#include "loguru.hpp"
#include <signal.h>
#include <thread>

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
  std::unique_ptr<CThreadPool> ThreadPool;
  std::unique_ptr<CPoolInstance> Instance;
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
  unsigned workerThreadsNum = 0;

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

  CConfig config;
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
      char logFileName[256];
      auto t = time(nullptr);
      auto now = localtime(&t);
      snprintf(logFileName, sizeof(logFileName), "mine_svc-%s-%s-%04u-%02u-%02u.log", config.Name.c_str(), config.UniqueId.c_str(), now->tm_year + 1900, now->tm_mon + 1, now->tm_mday);
      std::filesystem::path logFilePath(poolContext.DatabasePath);
      loguru::add_file((poolContext.DatabasePath / logFileName).generic_string().c_str(), loguru::Append, loguru::Verbosity_1);
    }

    workerThreadsNum = config.WorkerThreadsNum;
    if (workerThreadsNum == 0)
      workerThreadsNum = std::thread::hardware_concurrency() ? std::thread::hardware_concurrency() / 4 : 2;

    // Initialize workers
    poolContext.ThreadPool.reset(new CThreadPool(workerThreadsNum));

    {
      UserManager *nullManager = nullptr;
      std::vector<PoolBackend*> linkedBackends;

      // Get linked backends
      for (const auto &linkedCoinName: config.Backends) {
        linkedBackends.push_back(nullptr);
      }


      CPoolInstance *instance = PoolInstanceFabric::get(monitorBase,
                                                        *nullManager,
                                                        linkedBackends,
                                                        *poolContext.ThreadPool,
                                                        config.Type,
                                                        config.Protocol,
                                                        static_cast<unsigned>(0),
                                                        static_cast<unsigned>(1),
                                                        config.InstanceConfig);
      if (!instance) {
        LOG_F(ERROR, "Can't create instance with type '%s' and prorotol '%s'", config.Type.c_str(), config.Protocol.c_str());
        return 1;
      }

      std::string algo;
      for (PoolBackend *linkedBackend: linkedBackends) {
        if (!algo.empty() && linkedBackend->getCoinInfo().Algorithm != algo) {
          LOG_F(ERROR, "Linked backends with different algorithms (%s and %s) to one instance %s", algo.c_str(), linkedBackend->getCoinInfo().Algorithm.c_str(), config.Name.c_str());
          return 1;
        }

        algo = linkedBackend->getCoinInfo().Algorithm;

        linkedBackend->getClientDispatcher().connectWith(instance);
        // TODO: send linked backend list to instance
        instance->setAlgoMetaStatistic(linkedBackend->getAlgoMetaStatistic());
      }

      poolContext.Instance.reset(instance);
    }
  }

  // Start workers
  poolContext.ThreadPool->start();

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
    // Stop workers
    poolContext.ThreadPool->stop();

    // Stop monitor thread
    postQuitOperation(monitorBase);
  });

  sigIntThread.detach();
  monitorThread.join();
  LOG_F(INFO, "pool_mine_svc stopped\n");
  return 0;
}
