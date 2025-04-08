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
  std::unique_ptr<CNetworkClientDispatcher> ClientDispatcher;
  std::unique_ptr<PoolBackend> Backend;
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
      snprintf(logFileName, sizeof(logFileName), "%s-accounting-%04u-%02u-%02u.log", config.Name.c_str(), now->tm_year + 1900, now->tm_mon + 1, now->tm_mday);
      std::filesystem::path logFilePath(poolContext.DatabasePath);
      loguru::add_file((poolContext.DatabasePath / logFileName).generic_string().c_str(), loguru::Append, loguru::Verbosity_1);
    }

    std::map<std::string, StatisticServer*> knownAlgo;
    {
      PoolBackendConfig backendConfig;
      const char *coinName = config.Name.c_str();
      CCoinInfo coinInfo = CCoinLibrary::get(coinName);

      // Inherited pool config parameters
      backendConfig.dbPath = poolContext.DatabasePath / coinInfo.Name;

      // Backend parameters
      if (!parseMoneyValue(config.DefaultPayoutThreshold.c_str(), coinInfo.RationalPartSize, &backendConfig.DefaultPayoutThreshold)) {
        LOG_F(ERROR, "Can't load 'defaultPayoutThreshold' from %s coin config", coinName);
        return 1;
      }

      if (!parseMoneyValue(config.MinimalAllowedPayout.c_str(), coinInfo.RationalPartSize, &backendConfig.MinimalAllowedPayout)) {
        LOG_F(ERROR, "Can't load 'minimalPayout' from %s coin config", coinName);
        return 1;
      }

      if (config.RequiredConfirmations < coinInfo.MinimalConfirmationsNumber) {
        LOG_F(ERROR, "Minimal required confirmations for %s is %u", coinInfo.Name.c_str(), coinInfo.MinimalConfirmationsNumber);
        return 1;
      }

      backendConfig.RequiredConfirmations = config.RequiredConfirmations;
      backendConfig.KeepRoundTime = config.KeepRoundTime * 24*3600;
      backendConfig.KeepStatsTime = config.KeepStatsTime * 60;
      backendConfig.ConfirmationsCheckInterval = config.ConfirmationsCheckInterval * 60 * 1000000;
      backendConfig.PayoutInterval = config.PayoutInterval * 60 * 1000000;
      backendConfig.BalanceCheckInterval = config.BalanceCheckInterval * 60 * 1000000;

      for (const auto &addr: config.MiningAddresses) {
        if (!coinInfo.checkAddress(addr.Address, coinInfo.PayoutAddressType)) {
          LOG_F(ERROR, "Invalid mining address: %s", addr.Address.c_str());
          return 1;
        }

        backendConfig.MiningAddresses.add(CMiningAddress(addr.Address, addr.PrivateKey), addr.Weight);
      }

      backendConfig.CoinBaseMsg = config.CoinbaseMsg;

      // ZEC specific
      backendConfig.poolZAddr = config.PoolZAddr;
      backendConfig.poolTAddr = config.PoolTAddr;

      // Nodes
      std::unique_ptr<CNetworkClientDispatcher> dispatcher(new CNetworkClientDispatcher(monitorBase, coinInfo, 1 + 1));
      for (size_t nodeIdx = 0, nodeIdxE = config.GetWorkNodes.size(); nodeIdx != nodeIdxE; ++nodeIdx) {
        CNetworkClient *client;
        const CNodeConfig &node = config.GetWorkNodes[nodeIdx];
        if (node.Type == "bitcoinrpc") {
          client = new CBitcoinRpcClient(monitorBase, 1 + 1, coinInfo, node.Address.c_str(), node.Login.c_str(), node.Password.c_str(), node.LongPollEnabled);
        } else if (node.Type == "ethereumrpc") {
          client = new CEthereumRpcClient(monitorBase, 1 + 1, coinInfo, node.Address.c_str(), backendConfig);
        } else {
          LOG_F(ERROR, "Unknown node type: %s", node.Type.c_str());
          return 1;
        }

        dispatcher->addGetWorkClient(client);
      }

      for (size_t nodeIdx = 0, nodeIdxE = config.RPCNodes.size(); nodeIdx != nodeIdxE; ++nodeIdx) {
        CNetworkClient *client;
        const CNodeConfig &node = config.RPCNodes[nodeIdx];
        if (node.Type == "bitcoinrpc") {
          client = new CBitcoinRpcClient(monitorBase, 1 + 1, coinInfo, node.Address.c_str(), node.Login.c_str(), node.Password.c_str(), node.LongPollEnabled);
        } else if (node.Type == "ethereumrpc") {
          client = new CEthereumRpcClient(monitorBase, 1 + 1, coinInfo, node.Address.c_str(), backendConfig);
        } else {
          LOG_F(ERROR, "Unknown node type: %s", node.Type.c_str());
          return 1;
        }

        dispatcher->addRPCClient(client);
      }

      // Initialize price fetcher
      CPriceFetcher *priceFetcher = new CPriceFetcher(monitorBase, coinInfo);

      // Initialize backend
      PoolBackend *backend = new PoolBackend(createAsyncBase(amOSDefault), std::move(backendConfig), coinInfo, *dispatcher, *priceFetcher);

      if (config.ProfitSwitchCoeff != 0.0)
        backend->setProfitSwitchCoeff(config.ProfitSwitchCoeff);

      poolContext.Backend.reset(backend);
      poolContext.ClientDispatcher.reset(dispatcher.release());
    }
  }

  poolContext.Backend->start();
  poolContext.ClientDispatcher->poll();

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
    poolContext.Backend->stop();
    // Stop monitor thread
    postQuitOperation(monitorBase);
  });

  sigIntThread.detach();
  monitorThread.join();
  LOG_F(INFO, "poolfrondend stopped\n");
  return 0;
}
