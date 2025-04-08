#include "asyncio/asyncio.h"
#include "asyncio/socket.h"
#include "poolcommon/file.h"
#include "poolcore/usermgr.h"
#include "http.h"

#include "loguru.hpp"
#include <signal.h>
#include <stdio.h>

#if !defined(OS_WINDOWS)
#include <netdb.h>
#endif

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
  uint16_t HttpPort;
  std::unique_ptr<UserManager> UserMgr;
  std::unique_ptr<PoolHttpServer> HttpServer;
};

// TODO: move to poolcommon
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
  unsigned httpThreadsNum = 0;

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

  CPoolFrontendConfig config;
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
      snprintf(logFileName, sizeof(logFileName), "master-%04u-%02u-%02u.log", now->tm_year + 1900, now->tm_mon + 1, now->tm_mday);
      std::filesystem::path logFilePath(poolContext.DatabasePath);
      loguru::add_file((poolContext.DatabasePath / logFileName).generic_string().c_str(), loguru::Append, loguru::Verbosity_1);
    }

    // Analyze config
    poolContext.HttpPort = config.HttpPort;
    httpThreadsNum = config.HttpThreadsNum;
    if (httpThreadsNum == 0)
      httpThreadsNum = 1;

    // Initialize user manager
    poolContext.UserMgr.reset(new UserManager(poolContext.DatabasePath));

    // Base config
    poolContext.UserMgr->setBaseCfg(config.PoolName,
                                    config.PoolHostProtocol,
                                    config.PoolHostAddress,
                                    config.PoolActivateLinkPrefix,
                                    config.PoolChangePasswordLinkPrefix,
                                    config.PoolActivate2faLinkPrefix,
                                    config.PoolDeactivate2faLinkPrefix);

    // Admin & observer passwords
    if (!config.AdminPasswordHash.empty())
      poolContext.UserMgr->addSpecialUser(UserManager::ESpecialUserAdmin, config.AdminPasswordHash);
    if (!config.ObserverPasswordHash.empty())
      poolContext.UserMgr->addSpecialUser(UserManager::ESpecialUserObserver, config.ObserverPasswordHash);

    // SMTP config
    if (config.SmtpEnabled) {
      // Build HostAddress for server
      HostAddress smtpAddress;
      char *colonPos = (char*)strchr(config.SmtpServer.c_str(), ':');
      if (colonPos == nullptr) {
        LOG_F(ERROR, "Invalid server %s\nIt must have address:port format", config.SmtpServer.c_str());
        return 1;
      }

      *colonPos = 0;
      hostent *host = gethostbyname(config.SmtpServer.c_str());
      if (!host) {
        LOG_F(ERROR, "Cannot retrieve address of %s (gethostbyname failed)", config.SmtpServer.c_str());
      }

      u_long addr = host->h_addr ? *reinterpret_cast<u_long*>(host->h_addr) : 0;
      if (!addr) {
        LOG_F(ERROR, "Cannot retrieve address of %s (gethostbyname returns 0)", config.SmtpServer.c_str());
        return 1;
      }

      smtpAddress.family = AF_INET;
      smtpAddress.ipv4 = static_cast<uint32_t>(addr);
      smtpAddress.port = htons(atoi(colonPos + 1));

      // Enable SMTP
      poolContext.UserMgr->enableSMTP(smtpAddress, config.SmtpLogin, config.SmtpPassword, config.SmtpSenderAddress, config.SmtpUseSmtps, config.SmtpUseStartTls);
    }
  }

  // Start user manager
  poolContext.UserMgr->start();

  poolContext.HttpServer.reset(new PoolHttpServer(poolContext.HttpPort, *poolContext.UserMgr, config, httpThreadsNum));
  poolContext.HttpServer->start();

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
    // Stop HTTP server
    poolContext.HttpServer->stop();
    // Stop user manager
    poolContext.UserMgr->stop();

    // Stop monitor thread
    postQuitOperation(monitorBase);
  });

  sigIntThread.detach();
  monitorThread.join();
  LOG_F(INFO, "pool_master_svc stopped\n");
  return 0;
}
