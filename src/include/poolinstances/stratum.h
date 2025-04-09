#pragma once

#include "common.h"
#include "stratumMsg.h"
#include "stratumWorkStorage.h"
#include "poolcommon/arith_uint256.h"
#include "poolcommon/debug.h"
#include "poolcommon/jsonSerializer.h"
#include "poolcore/backend.h"
#include "poolcore/blockTemplate.h"
#include "poolcore/poolCore.h"
#include "poolcore/poolInstance.h"
#include <openssl/rand.h>
#include <rapidjson/writer.h>
#include <unordered_map>

static constexpr unsigned UncheckedSendCount = 32;
static constexpr uint64_t SendTimeout = 4000000;

enum StratumErrorTy {
  StratumErrorInvalidShare = 20,
  StratumErrorJobNotFound = 21,
  StratumErrorDuplicateShare = 22,
  StratumErrorUnauthorizedWorker = 24
};

static inline const char *stratumErrorText(StratumErrorTy error)
{
  switch (error) {
    case StratumErrorInvalidShare : return "invalid_share";
    case StratumErrorJobNotFound : return "stale_share";
    case StratumErrorDuplicateShare : return "duplicate_share";
    case StratumErrorUnauthorizedWorker : return "unauthorized_worker";
    default : return "error";
  }
}

template<typename T>
static inline unsigned popcount(T number)
{
  unsigned count = 0;
  for(; number; count++)
    number &= number-1;
  return count;
}

template<typename X>
class StratumInstance : public CPoolInstance {
public:
  using CWork = StratumWork<typename X::Proto::BlockHashTy, typename X::Stratum::StratumMessage>;
  using CSingleWork = StratumSingleWork<typename X::Proto::BlockHashTy, typename X::Stratum::StratumMessage>;
  using CMergedWork = StratumMergedWork<typename X::Proto::BlockHashTy, typename X::Stratum::StratumMessage>;

public:
  StratumInstance(asyncBase *monitorBase,
                  UserManager &userMgr,
                  const std::vector<PoolBackend*> &linkedBackends,
                  CThreadPool &threadPool,
                  unsigned instanceId,
                  unsigned instancesNum,
                  rapidjson::Value &config) : CPoolInstance(monitorBase, userMgr, threadPool), CurrentThreadId_(0) {
    Data_.reset(new ThreadData[threadPool.threadsNum()]);

    unsigned totalInstancesNum = instancesNum * threadPool.threadsNum();
    for (unsigned i = 0; i < threadPool.threadsNum(); i++) {
      bool hasRtt = false;

      // initialInstanceId used for fixed extra nonce part calculation
      unsigned initialInstanceId = instanceId*threadPool.threadsNum() + i;
      Data_[i].ThreadCfg.initialize(initialInstanceId, totalInstancesNum);
      Data_[i].WorkerBase = threadPool.getBase(i);
      {
        std::vector<std::pair<PoolBackend*, bool>> backendsWithInfo;
        for (PoolBackend *backend: linkedBackends) {
          hasRtt |= backend->getCoinInfo().HasRtt;
          backendsWithInfo.push_back(std::make_pair(backend, X::Stratum::isMainBackend(backend->getCoinInfo().Name)));
        }
        Data_[i].WorkStorage.init(backendsWithInfo);
      }
      if (hasRtt) {
        Data_[i].Timer = newUserEvent(Data_[i].WorkerBase, false, [](aioUserEvent*, void *arg) {
          ((StratumInstance*)(arg))->rttTimerCb();
        }, this);
        userEventStartTimer(Data_[i].Timer, 1000000, 0);
      }
    }

    if (!config.HasMember("port") || !config["port"].IsUint()) {
      LOG_F(ERROR, "instance %s: can't read 'port' valuee from config", Name_.c_str());
      exit(1);
    }

    uint16_t port = config["port"].GetInt();
    Name_ += ".";
    Name_ += std::to_string(port);

    // Share diff
    if (config.HasMember("shareDiff")) {
      if (config["shareDiff"].IsUint64()) {
        ConstantShareDiff_ = static_cast<double>(config["shareDiff"].GetUint64());
      } else if (config["shareDiff"].IsFloat()) {
        ConstantShareDiff_ = config["shareDiff"].GetFloat();
      } else {
        LOG_F(ERROR, "%s: 'shareDiff' must be an integer", Name_.c_str());
        exit(1);
      }
    } else if (config.HasMember("varDiffTarget") && config.HasMember("minShareDiff")) {
      LOG_F(ERROR, "%s: Vardiff not supported now", Name_.c_str());
      exit(1);
    } else {
      LOG_F(ERROR, "instance %s: no share difficulty config (expected 'shareDiff' for constant difficulty or 'varDiffTarget' and 'minShareDiff' for variable diff", Name_.c_str());
      exit(1);
    }

    if (!config.HasMember("backends") || !config["backends"].IsArray()) {
      LOG_F(ERROR, "instance %s: no backends specified", Name_.c_str());
      exit(1);
    }

    // BTC ASIC boost
    if (config.HasMember("versionMask") && config["versionMask"].IsString())
      VersionMask_ = readHexBE<uint32_t>(config["versionMask"].GetString(), 4);

    // Profit switcher
    if (config.HasMember("profitSwitcherEnabled") && config["profitSwitcherEnabled"].IsBool())
      ProfitSwitcherEnabled_ = config["profitSwitcherEnabled"].GetBool();

    X::Stratum::miningConfigInitialize(MiningCfg_, config);

    // Main listener
    createListener(monitorBase, port, [](socketTy socket, HostAddress address, void *arg) { static_cast<StratumInstance*>(arg)->newFrontendConnection(socket, address); }, this);
  }

  virtual void checkNewBlockTemplate(CBlockTemplate *blockTemplate, PoolBackend *backend) override {
    for (unsigned i = 0; i < ThreadPool_.threadsNum(); i++)
      ThreadPool_.startAsyncTask(i, new AcceptWork(*this, blockTemplate, backend));
    if (MiningStats_)
      MiningStats_->onWork(blockTemplate->Difficulty, backend);
  }

  virtual void stopWork() override {
    for (unsigned i = 0; i < ThreadPool_.threadsNum(); i++)
      ThreadPool_.startAsyncTask(i, new AcceptWork(*this, nullptr, nullptr));
  }

  void acceptConnection(unsigned workerId, socketTy socketFd, HostAddress address) {
    ThreadData &data = Data_[workerId];
    aioObject *socket = newSocketIo(data.WorkerBase, socketFd);
    Connection *connection = new Connection(this, socket, workerId, address);
    objectSetDestructorCb(aioObjectHandle(socket), [](aioObjectRoot*, void *arg) {
      delete static_cast<Connection*>(arg);
    }, connection);

    X::Stratum::workerConfigInitialize(connection->WorkerConfig, data.ThreadCfg);
    if (isDebugInstanceStratumConnections())
      LOG_F(1, "%s: new connection from %s", Name_.c_str(), connection->AddressHr.c_str());

    // Initialize share difficulty
    connection->ShareDifficulty = ConstantShareDiff_;

    aioRead(connection->Socket, connection->Buffer, sizeof(connection->Buffer), afNone, 3000000, reinterpret_cast<aioCb*>(readCb), connection);
  }

  void acceptWork(CBlockTemplate *blockTemplate, PoolBackend *backend) {
    if (!blockTemplate) {
      return;
    }

    ThreadData &data = Data_[GetLocalThreadId()];
    typename X::Proto::AddressTy miningAddress;
    auto &backendConfig = backend->getConfig();
    auto &coinInfo = backend->getCoinInfo();
    const std::string &addr = backendConfig.MiningAddresses.get().MiningAddress;
    if (!X::Proto::decodeHumanReadableAddress(addr, coinInfo.PubkeyAddressPrefix, miningAddress)) {
      LOG_F(WARNING, "%s: mining address %s is invalid", coinInfo.Name.c_str(), addr.c_str());
      return;
    }

    bool isNewBlock = false;
    std::vector<uint8_t> miningAddressData(miningAddress.begin(), miningAddress.end());
    if (!data.WorkStorage.createWork(*blockTemplate, backend, coinInfo.Name, miningAddressData, backendConfig.CoinBaseMsg, MiningCfg_, Name_, &isNewBlock))
      return;

    CWork *work = nullptr;
    if (ProfitSwitcherEnabled_) {
      // Search most profitable work
      auto calculateProfit = [](CWork *work) -> double {
        double result = 0.0;
        for (size_t i = 0, ie = work->backendsNum(); i != ie; ++i) {
          PoolBackend *backend = work->backend(i);
          if (!backend)
            continue;

          result += work->getAbstractProfitValue(i, backend->getPriceFetcher().getPrice(), backend->getProfitSwitchCoeff());
        }

        return result;
      };

      std::vector<std::pair<CWork*, double>> allWorks;
      for (size_t i = 0; i < LinkedBackends_.size(); i++) {
        CWork *nextWork = data.WorkStorage.singleWork(i);
        if (!nextWork || !nextWork->ready())
          continue;

        allWorks.emplace_back(nextWork, calculateProfit(nextWork));
      }

      for (size_t i = 0; i < LinkedBackends_.size(); i++) {
        for (size_t j = 0; j < LinkedBackends_.size(); j++) {
          CWork *nextWork = data.WorkStorage.mergedWork(i, j);
          if (!nextWork || !nextWork->ready() || !nextWork->backend(0) || !nextWork->backend(1))
            continue;

          allWorks.emplace_back(nextWork, calculateProfit(nextWork));
        }
      }

      std::sort(allWorks.begin(), allWorks.end(), [](const auto &l, const auto &r) { return l.second < r.second; });
      if (!allWorks.empty() && allWorks.back().first != data.WorkStorage.currentWork()) {
        work = allWorks.back().first;

        std::string profitSwitcherInfo;
        for (auto I = allWorks.rbegin(), IE = allWorks.rend(); I != IE; ++I) {
          char buffer[64];
          snprintf(buffer, sizeof(buffer), "%.8lf", I->second);
          profitSwitcherInfo.push_back(' ');
          profitSwitcherInfo.append(workName(I->first));
          profitSwitcherInfo.push_back('(');
          profitSwitcherInfo.append(buffer);
          profitSwitcherInfo.push_back(')');
        }

        if (GetLocalThreadId() == 0)
          LOG_F(INFO, "[t=0] %s: ProfitSwitcher:%s", Name_.c_str(), profitSwitcherInfo.c_str());
      }
    } else {
      // Switch to last accepted work
      work = data.WorkStorage.lastAcceptedWork();
    }

    if (work && work->ready()) {
      // Send work to all miners
      auto beginPt = std::chrono::steady_clock::now();
      data.WorkStorage.setCurrentWork(work);

      // If previous work has been updated (new block came), we need send 'true' as a last field of stratum.notify
      bool resetPreviousWork = isNewBlock && !X::Stratum::keepOldWorkForBackend(coinInfo.Name);

      work->buildNotifyMessage(resetPreviousWork);
      int64_t currentTime = time(nullptr);
      unsigned counter = 0;
      for (auto &connection: data.Connections_) {
        connection->ResendCount = 0;
        stratumSendWork(connection, work, currentTime);
        counter++;
      }

      auto endPt = std::chrono::steady_clock::now();
      auto timeDiff = std::chrono::duration_cast<std::chrono::milliseconds>(endPt - beginPt).count();
      if (GetLocalThreadId() == 0)
        LOG_F(INFO, "[t=0] %s: Broadcast %s work %" PRIi64 "(reset=%s) & send to %u clients in %.3lf seconds", Name_.c_str(), workName(work).c_str(), work->stratumId(), resetPreviousWork ? "yes" : "no", counter, static_cast<double>(timeDiff)/1000.0);
    }
  }

private:
  class AcceptNewConnection : public CThreadPool::Task {
  public:
    AcceptNewConnection(StratumInstance &instance, socketTy socketFd, HostAddress address) : Instance_(instance), SocketFd_(socketFd), Address_(address) {}
    void run(unsigned workerId) final { Instance_.acceptConnection(workerId, SocketFd_, Address_); }
  private:
    StratumInstance &Instance_;
    socketTy SocketFd_;
    HostAddress Address_;
  };

  class AcceptWork : public CThreadPool::Task {
  public:
    AcceptWork(StratumInstance &instance, CBlockTemplate *blockTemplate, PoolBackend *backend) : Instance_(instance), BlockTemplate_(blockTemplate), Backend_(backend) {}
    void run(unsigned) final { Instance_.acceptWork(BlockTemplate_.get(), Backend_); }
  private:
    StratumInstance &Instance_;
    intrusive_ptr<CBlockTemplate> BlockTemplate_;
    PoolBackend *Backend_;
  };

  struct Worker {
    std::string User;
    std::string WorkerName;
  };

  struct Connection {
    Connection(StratumInstance *instance, aioObject *socket, unsigned workerId, HostAddress address) : Instance(instance), Socket(socket), WorkerId(workerId), Address(address) {
      struct in_addr addr;
      addr.s_addr = Address.ipv4;
      AddressHr = inet_ntoa(addr);
      AddressHr.push_back(':');
      AddressHr.append(std::to_string(htons(address.port)));
    }

    ~Connection() {
      if (isDebugInstanceStratumConnections())
        LOG_F(1, "%s: disconnected from %s", Instance->Name_.c_str(), AddressHr.c_str());
      Instance->Data_[WorkerId].Connections_.erase(this);
    }

    void close() {
      if (Active) {
        deleteAioObject(Socket);
        Active = false;
      }
    }

    bool Initialized = false;
    StratumInstance *Instance;
    // Network
    aioObject *Socket;
    unsigned WorkerId;
    HostAddress Address;
    std::string AddressHr;
    unsigned SendCounter_ = 0;
    bool Active = true;
    bool IsCgMiner = false;
    bool IsNiceHash = false;
    int64_t LastUpdateTime = std::numeric_limits<int64_t>::max();
    // Stratum protocol decoding
    char Buffer[12288];
    size_t MsgTailSize = 0;
    // Mining info
    CWorkerConfig WorkerConfig;
    // Current share difficulty (one for all workers on connection)
    double ShareDifficulty;
    // Workers
    std::unordered_map<std::string, Worker> Workers;
    // Share statistic
    static constexpr unsigned SSWindowSize = 10;
    static constexpr unsigned SSWindowElementSize = 10;

    // TODO use cycle buffer here
    std::deque<uint32_t> InvalidShares;
    unsigned TotalSharesCounter = 0;
    unsigned InvalidSharesCounter = 0;
    unsigned InvalidSharesSequenceSize = 0;
    unsigned ResendCount = 0;
  };

  struct ThreadData {
    asyncBase *WorkerBase;
    ThreadConfig ThreadCfg;
    std::set<Connection*> Connections_;
    StratumWorkStorage<X> WorkStorage;
    aioUserEvent *Timer;
  };

private:
  void send(Connection *connection, const xmstream &stream) {
    if (isDebugInstanceStratumMessages()) {
      std::string msg(stream.data<char>(), stream.sizeOf());
      LOG_F(1, "%s(%s): outgoing message %s", connection->Instance->Name_.c_str(), connection->AddressHr.c_str(), msg.c_str());
    }
    if (++connection->SendCounter_ < UncheckedSendCount) {
      aioWrite(connection->Socket, stream.data(), stream.sizeOf(), afWaitAll, 0, nullptr, nullptr);
    } else {
      aioWrite(connection->Socket, stream.data(), stream.sizeOf(), afWaitAll, SendTimeout, [](AsyncOpStatus status, aioObject*, size_t, void *arg) {
        if (status != aosSuccess) {
          Connection *connection = static_cast<Connection*>(arg);
          LOG_F(1, "%s: send timeout to %s", connection->Instance->Name_.c_str(), connection->AddressHr.c_str());
          connection->close();
        }
      }, connection);
      connection->SendCounter_ = 0;
    }
  }

  void onStratumSubscribe(Connection *connection, typename X::Stratum::StratumMessage &msg) {
    if (msg.Subscribe.minerUserAgent.find("cgminer") != std::string::npos)
      connection->IsCgMiner = true;
    if (msg.Subscribe.minerUserAgent.find("NiceHash") != std::string::npos) {
      connection->IsNiceHash = true;
      if (AlgoMetaStatistic_->coinInfo().Name == "sha256") {
        connection->ShareDifficulty = std::max(500000.0, connection->ShareDifficulty);
      } else if (AlgoMetaStatistic_->coinInfo().Name == "scrypt") {
        connection->ShareDifficulty = std::max(10.0, connection->ShareDifficulty);
      } else if (AlgoMetaStatistic_->coinInfo().Name == "equihash.200.9") {
        connection->ShareDifficulty = std::max(131072.0, connection->ShareDifficulty);
      }
    }

    std::string subscribeInfo;
    char buffer[4096];
    xmstream stream(buffer, sizeof(buffer));
    stream.reset();
    X::Stratum::workerConfigOnSubscribe(connection->WorkerConfig, MiningCfg_, msg, stream, subscribeInfo);
    send(connection, stream);
    if (isDebugInstanceStratumConnections())
      LOG_F(1, "%s(%s): subscribe data: %s", connection->Instance->Name_.c_str(), connection->AddressHr.c_str(), subscribeInfo.c_str());
  }

  bool onStratumAuthorize(Connection *connection, typename X::Stratum::StratumMessage &msg) {
    bool authSuccess = false;
    std::string error;
    size_t dotPos = msg.Authorize.login.find('.');
    if (dotPos != msg.Authorize.login.npos) {
      Worker worker;
      worker.User.assign(msg.Authorize.login.begin(), msg.Authorize.login.begin() + dotPos);
      worker.WorkerName.assign(msg.Authorize.login.begin() + dotPos + 1, msg.Authorize.login.end());
      connection->Workers.insert(std::make_pair(msg.Authorize.login, worker));
      authSuccess = UserMgr_.checkUser(worker.User);
    } else {
      error = "Invalid user name format (username.workername required)";
    }

    char buffer[4096];
    xmstream stream(buffer, sizeof(buffer));
    stream.reset();
    {
      JSON::Object object(stream);
      msg.addId(object);
      object.addBoolean("result", authSuccess);
      if (authSuccess)
        object.addNull("error");
      else
        object.addString("error", error);
    }
    stream.write('\n');
    send(connection, stream);
    return authSuccess;
  }

  bool onStratumMiningConfigure(Connection *connection, typename X::Stratum::StratumMessage &msg) {
    xmstream stream;
    std::string error;
    {
      JSON::Object object(stream);
      msg.addId(object);
      object.addField("result");
      {
        JSON::Object result(stream);
        if (msg.MiningConfigure.ExtensionsField & StratumMiningConfigure::EVersionRolling) {
          bool versionRolling = false;
          // Workaround about ASICs that not send "version-rolling.min-bit-count"
          if (msg.MiningConfigure.VersionRollingMask.has_value() && !msg.MiningConfigure.VersionRollingMinBitCount.has_value())
            msg.MiningConfigure.VersionRollingMinBitCount = 2;
          if (msg.MiningConfigure.VersionRollingMask.has_value() && msg.MiningConfigure.VersionRollingMinBitCount.has_value()) {
            // Calculate target bit mask
            uint32_t targetBitMask = msg.MiningConfigure.VersionRollingMask.value() & VersionMask_;
            // Get target bit count
            // TODO: use std::popcount since C++20
            unsigned count = popcount(targetBitMask);
            if (count >= msg.MiningConfigure.VersionRollingMinBitCount.value()) {
              result.addString("version-rolling.mask", writeHexBE(targetBitMask, 4));
              // TODO: write error if asic boost not supported
              X::Stratum::workerConfigSetupVersionRolling(connection->WorkerConfig, targetBitMask);
              versionRolling = true;
            }
          }

          if (!versionRolling) {
            struct in_addr addr;
            addr.s_addr = connection->Address.ipv4;
            // TODO: change to DEBUG
            LOG_F(WARNING,
                  "%s: can't setup version rolling for %s (client mask: %X; minimal bit count: %X, server mask: %X)",
                  connection->Instance->Name_.c_str(),
                  inet_ntoa(addr),
                  msg.MiningConfigure.VersionRollingMask.has_value() ? msg.MiningConfigure.VersionRollingMask.value() : 0,
                  msg.MiningConfigure.VersionRollingMinBitCount.has_value() ? msg.MiningConfigure.VersionRollingMinBitCount.value() : 0,
                  VersionMask_);
          }
          result.addBoolean("version-rolling", versionRolling);
        }

        if (msg.MiningConfigure.ExtensionsField & StratumMiningConfigure::EMinimumDifficulty) {
          bool minimumDifficulty = false;
          result.addBoolean("minimum-difficulty", minimumDifficulty);
        }

        if (msg.MiningConfigure.ExtensionsField & StratumMiningConfigure::ESubscribeExtraNonce) {
          bool subscribeExtraNonce = false;
          result.addBoolean("subscribe-extranonce", subscribeExtraNonce);
        }
      }

      object.addNull("error");
    }

    stream.write('\n');
    send(connection, stream);

    ThreadData &data = Data_[GetLocalThreadId()];
    CWork *currentWork = data.WorkStorage.currentWork();
    if (connection->IsCgMiner && currentWork)
      stratumSendWork(connection, currentWork, time(nullptr));
    return true;
  }

  void onStratumMiningSuggestDifficulty(Connection*, typename X::Stratum::StratumMessage&) {
    // Nothing to do
  }

  void onStratumExtraNonceSubscribe(Connection *connection, typename X::Stratum::StratumMessage &message) {
    xmstream stream;
    {
      JSON::Object object(stream);
//      addId(object, message);
      message.addId(object);
      object.addBoolean("result", true);
      object.addNull("error");
    }

    stream.write('\n');
    send(connection, stream);
  }

  void sharePendingCheck(size_t backendIdx,
                         std::string userName,
                         std::string workerName,
                         int64_t majorJobId,
                         double stratumDifficulty,
                         const CWorkerConfig &workerConfig,
                         typename X::Stratum::StratumMessage msg) {
    ThreadData &data = Data_[GetLocalThreadId()];
    CWork *work = data.WorkStorage.workById(majorJobId);
    if (!work)
      return;
    if (!work->prepareForSubmit(workerConfig, msg))
      return;

    PoolBackend *backend = work->backend(backendIdx);
    if (!backend)
      return;

    // skip non-rtt backends
    if (!work->hasRtt(backendIdx))
      return;

    CCheckStatus checkStatus = work->checkConsensus(backendIdx);
    if (checkStatus.IsBlock) {
      std::string blockHash = work->blockHash(backendIdx);
      LOG_F(INFO, "%s: pending proof of work %s sending; hash: %s; transactions: %zu", Name_.c_str(), backend->getCoinInfo().Name.c_str(), blockHash.c_str(), work->txNum(backendIdx));

      // Serialize block
      xmstream blockHexData;
      work->buildBlock(backendIdx, blockHexData);
      uint64_t height = work->height(backendIdx);
      double expectedWork = work->expectedWork(backendIdx);
      int64_t generatedCoins = work->blockReward(backendIdx);
      CNetworkClientDispatcher &dispatcher = backend->getClientDispatcher();
      dispatcher.aioSubmitBlock(data.WorkerBase, blockHexData.data(), blockHexData.sizeOf(), [height, blockHash, generatedCoins, expectedWork, backend, stratumDifficulty, userName, workerName](bool success, uint32_t successNum, const std::string &hostName, const std::string &error) {
        if (success) {
          LOG_F(INFO, "* block %s (%" PRIu64 ") accepted by %s", blockHash.c_str(), height, hostName.c_str());
          if (successNum == 1) {
            // Send share with block to backend
            CShare *backendShare = new CShare;
            backendShare->Time = time(nullptr);
            backendShare->userId = userName;
            backendShare->workerId = workerName;
            backendShare->height = height;
            backendShare->WorkValue = stratumDifficulty;
            backendShare->isBlock = true;
            backendShare->hash = blockHash;
            backendShare->generatedCoins = generatedCoins;
            backendShare->ExpectedWork = expectedWork;
            backend->sendShare(backendShare);
          }
        } else {
          LOG_F(ERROR, "* block %s (%" PRIu64 ") rejected by %s error: %s", blockHash.c_str(), height, hostName.c_str(), error.c_str());
        }
      });
    }
  }

  bool shareCheck(Connection *connection, typename X::Stratum::StratumMessage &msg, StratumErrorTy &errorCode) {
    ThreadData &data = Data_[GetLocalThreadId()];
    uint64_t height = 0;
    CCheckStatus checkStatus;
    std::string blockHash;
    std::vector<bool> foundBlockMask(LinkedBackends_.size(), false);

    // Check worker name
    auto It = connection->Workers.find(msg.Submit.WorkerName);
    if (It == connection->Workers.end()) {
      if (isDebugInstanceStratumRejects())
        LOG_F(1, "%s(%s) reject: unknown worker name: %s", connection->Instance->Name_.c_str(), connection->AddressHr.c_str(), msg.Submit.WorkerName.c_str());
      errorCode = StratumErrorUnauthorizedWorker;
      return false;
    }
    Worker &worker = It->second;

    // Check job id
    CWork *work = nullptr;

    {
      size_t sharpPos = msg.Submit.JobId.find('#');
      if (sharpPos == msg.Submit.JobId.npos) {
        if (isDebugInstanceStratumRejects())
          LOG_F(1, "%s(%s) %s/%s reject: invalid job id format: %s", connection->Instance->Name_.c_str(), connection->AddressHr.c_str(), worker.User.c_str(), worker.WorkerName.c_str(), msg.Submit.JobId.c_str());
        errorCode = StratumErrorJobNotFound;
        return false;
      }

      msg.Submit.JobId[sharpPos] = 0;
      int64_t majorJobId = xatoi<uint64_t>(msg.Submit.JobId.c_str());
      work = data.WorkStorage.workById(majorJobId);
      if (!work) {
        if (isDebugInstanceStratumRejects())
          LOG_F(1, "%s(%s) %s/%s reject: unknown job id: %s", connection->Instance->Name_.c_str(), connection->AddressHr.c_str(), worker.User.c_str(), worker.WorkerName.c_str(), msg.Submit.JobId.c_str());
        errorCode = StratumErrorJobNotFound;
        return false;
      }
    }

    // Build header and check proof of work
    std::string user = worker.User;
    if (!work->prepareForSubmit(connection->WorkerConfig, msg)) {
      if (isDebugInstanceStratumRejects())
        LOG_F(1, "%s(%s) %s/%s reject: invalid share format", connection->Instance->Name_.c_str(), connection->AddressHr.c_str(), worker.User.c_str(), worker.WorkerName.c_str());
      errorCode = StratumErrorInvalidShare;
      return false;
    }

    // Check for duplicate
    typename X::Proto::BlockHashTy shareHash = work->shareHash();
    if (data.WorkStorage.isDuplicate(work, shareHash)) {
      if (isDebugInstanceStratumRejects())
        LOG_F(1, "%s(%s) %s/%s reject: duplicate share", connection->Instance->Name_.c_str(), connection->AddressHr.c_str(), worker.User.c_str(), worker.WorkerName.c_str());
      errorCode = StratumErrorDuplicateShare;
      return false;
    }

    // Loop over all affected backends (usually 1 or 2 with enabled merged mining)
    bool shareAccepted = false;
    for (size_t i = 0, ie = work->backendsNum(); i != ie; ++i) {
      PoolBackend *backend = work->backend(i);
      if (!backend) {
        if (isDebugInstanceStratumRejects())
          LOG_F(1, "%s(%s) %s/%s sub-reject: backend %zu not initialized", connection->Instance->Name_.c_str(), connection->AddressHr.c_str(), worker.User.c_str(), worker.WorkerName.c_str(), i);
        continue;
      }

      blockHash = work->blockHash(i);

      height = work->height(i);
      checkStatus = work->checkConsensus(i);

      if (checkStatus.ShareDiff < connection->ShareDifficulty) {
        if (isDebugInstanceStratumRejects())
          LOG_F(1,
                "%s(%s) %s/%s sub-reject(%s): invalid share difficulty %lg (%lg required)",
                connection->Instance->Name_.c_str(),
                connection->AddressHr.c_str(),
                worker.User.c_str(),
                worker.WorkerName.c_str(),
                backend->getCoinInfo().Name.c_str(),
                checkStatus.ShareDiff,
                connection->ShareDifficulty);
        continue;
      }

      shareAccepted = true;
      if (checkStatus.IsBlock) {
        LOG_F(INFO, "%s: new proof of work for %s found; hash: %s; transactions: %zu", Name_.c_str(), backend->getCoinInfo().Name.c_str(), blockHash.c_str(), work->txNum(i));

        // Serialize block
        xmstream blockHexData;
        work->buildBlock(i, blockHexData);

        int64_t generatedCoins = work->blockReward(i);
        double shareDifficulty = connection->ShareDifficulty;
        double expectedWork = work->expectedWork(i);
        CNetworkClientDispatcher &dispatcher = backend->getClientDispatcher();
        dispatcher.aioSubmitBlock(data.WorkerBase, blockHexData.data(), blockHexData.sizeOf(), [height, blockHash, generatedCoins, expectedWork, backend, shareDifficulty, worker](bool success, uint32_t successNum, const std::string &hostName, const std::string &error) {
          if (success) {
            LOG_F(INFO, "* block %s (%" PRIu64 ") accepted by %s", blockHash.c_str(), height, hostName.c_str());
            if (successNum == 1) {
              // Send share with block to backend
              CShare *backendShare = new CShare;
              backendShare->Time = time(nullptr);
              backendShare->userId = worker.User;
              backendShare->workerId = worker.WorkerName;
              backendShare->height = height;
              backendShare->WorkValue = shareDifficulty;
              backendShare->isBlock = true;
              backendShare->hash = blockHash;
              backendShare->generatedCoins = generatedCoins;
              backendShare->ExpectedWork = expectedWork;
              backend->sendShare(backendShare);
            }
          } else {
            LOG_F(ERROR, "* block %s (%" PRIu64 ") rejected by %s error: %s", blockHash.c_str(), height, hostName.c_str(), error.c_str());
          }
        });

        for (size_t i = 0, ie = LinkedBackends_.size(); i != ie; ++i) {
          if (LinkedBackends_[i] == backend) {
            foundBlockMask[i] = true;
            break;
          }
        }
      } else {
        CShare *backendShare = new CShare;
        backendShare->Time = time(nullptr);
        backendShare->userId = worker.User;
        backendShare->workerId = worker.WorkerName;
        backendShare->height = height;
        backendShare->WorkValue = connection->ShareDifficulty;
        backendShare->isBlock = false;
        backend->sendShare(backendShare);

        if (checkStatus.IsPendingBlock) {
          if (data.WorkStorage.updatePending(i, worker.User, worker.WorkerName, checkStatus.ShareDiff, connection->ShareDifficulty, xatoi<uint64_t>(msg.Submit.JobId.c_str()), connection->WorkerConfig, msg))
            LOG_F(INFO, "%s: new pending block %s found; hash: %s", Name_.c_str(), backend->getCoinInfo().Name.c_str(), blockHash.c_str());
        }
      }
    }

    if (!shareAccepted)
      errorCode = StratumErrorInvalidShare;

    if (shareAccepted && (AlgoMetaStatistic_ || true)) {
      CShare *backendShare = new CShare;
      backendShare->Time = time(nullptr);
      backendShare->userId = worker.User;
      backendShare->workerId = worker.WorkerName;
      backendShare->height = height;
      backendShare->WorkValue = connection->ShareDifficulty;
      backendShare->isBlock = false;
      if (AlgoMetaStatistic_)
        AlgoMetaStatistic_->sendShare(backendShare);

      // Share
      // All affected coins by this share
      // Difficulty of all affected coins
      if (MiningStats_)
        MiningStats_->onShare(checkStatus.ShareDiff, connection->ShareDifficulty, LinkedBackends_, foundBlockMask, shareHash);
    }

    return shareAccepted;
  }

  void onStratumSubmit(Connection *connection, typename X::Stratum::StratumMessage &msg) {
    StratumErrorTy errorCode;
    bool result = shareCheck(connection, msg, errorCode);

    // Update invalid shares statistic
    connection->TotalSharesCounter++;
    if (!result) {
      connection->InvalidSharesCounter++;
      connection->InvalidSharesSequenceSize++;
    } else {
      connection->InvalidSharesSequenceSize = 0;
    }

    if (connection->TotalSharesCounter == Connection::SSWindowElementSize) {
      connection->InvalidShares.push_back(connection->InvalidSharesCounter);
      connection->InvalidSharesCounter = 0;
      connection->TotalSharesCounter = 0;
      if (connection->InvalidShares.size() > Connection::SSWindowSize)
        connection->InvalidShares.pop_front();
    }

    xmstream stream;
    {
      // Response
      JSON::Object object(stream);
      msg.addId(object);
      if (result) {
        object.addBoolean("result", true);
        object.addNull("error");
      } else {
        object.addNull("result");
        object.addField("error");
        {
          JSON::Array error(stream);
          error.addInt(static_cast<int>(errorCode));
          error.addString(stratumErrorText(errorCode));
          error.addNull();
        }
      }
    }

    stream.write('\n');
    send(connection, stream);

    if (!result) {
      // Calculate invalid shares percentage
      uint32_t invalidSharedPercent = 0;
      if (connection->InvalidShares.size() >= 3) {
        uint32_t invalidShares = 0;
        for (auto v: connection->InvalidShares)
          invalidShares += v;
        invalidSharedPercent = invalidShares * 100 / (connection->InvalidShares.size()*Connection::SSWindowElementSize);
      }

      if (invalidSharedPercent >= 20) {
        if (isDebugInstanceStratumConnections())
          LOG_F(1, "%s: connection %s: too much errors, disconnecting...", Name_.c_str(), connection->AddressHr.c_str());
        connection->close();
        return;
      }

      // Change job for duplicate/invalid share (handle unstable clients)
      // Do it every 4 sequential invalid shares
      if ((errorCode == StratumErrorDuplicateShare || errorCode == StratumErrorInvalidShare) && (connection->InvalidSharesSequenceSize % 4 == 0)) {
        ThreadData &data = Data_[GetLocalThreadId()];
        // "Mutate" newest available work
        CWork *work = data.WorkStorage.currentWork();
        if (work) {
          work->mutate();
          connection->ResendCount++;
          stratumSendWork(connection, work, time(nullptr));
        }
      }
    }
  }

  void onStratumMultiVersion(Connection *connection, typename X::Stratum::StratumMessage &message) {
    xmstream stream;
    {
      JSON::Object object(stream);
      message.addId(object);
      object.addBoolean("result", true);
      object.addNull("error");
    }

    stream.write('\n');
    send(connection, stream);
  }

  void onStratumSubmitHashrate(Connection *connection, typename X::Stratum::StratumMessage &message) {
    xmstream stream;
    {
      JSON::Object object(stream);
      message.addId(object);
      object.addBoolean("result", true);
      object.addNull("error");
    }

    stream.write('\n');
    send(connection, stream);
  }

  void stratumSendTarget(Connection *connection) {
    xmstream stream;
    X::Stratum::buildSendTargetMessage(stream, connection->ShareDifficulty);
    stream.write('\n');
    send(connection, stream);
  }

  void stratumSendWork(Connection *connection, CWork *work, int64_t currentTime) {
    connection->LastUpdateTime = currentTime;
    send(connection, work->notifyMessage());
  }

  void newFrontendConnection(socketTy fd, HostAddress address) {
    // Functions runs inside 'monitor' thread
    // Send task to one of worker threads
    ThreadPool_.startAsyncTask(CurrentThreadId_, new AcceptNewConnection(*this, fd, address));
    CurrentThreadId_ = (CurrentThreadId_ + 1) % ThreadPool_.threadsNum();
  }

  static void readCb(AsyncOpStatus status, aioObject*, size_t size, Connection *connection) {
    if (status != aosSuccess) {
      connection->close();
      return;
    }

    ThreadData &data = connection->Instance->Data_[connection->WorkerId];
    if (!connection->Initialized) {
      data.Connections_.insert(connection);
      connection->Initialized = true;
    }

    const char *nextMsgPos;
    const char *p = connection->Buffer;
    const char *e = connection->Buffer + connection->MsgTailSize + size;
    while (p != e && (nextMsgPos = static_cast<const char*>(memchr(p, '\n', e - p)))) {
      // parse stratum message
      bool result = true;
      typename X::Stratum::StratumMessage msg;
      size_t stratumMsgSize = nextMsgPos - p;
      if (isDebugInstanceStratumMessages()) {
        std::string msg(p, stratumMsgSize);
        LOG_F(1, "%s(%s): incoming message %s", connection->Instance->Name_.c_str(), connection->AddressHr.c_str(), msg.c_str());
      }

      switch (msg.decodeStratumMessage(p, stratumMsgSize)) {
        case EStratumDecodeStatusTy::EStratumStatusOk :
          // Process stratum messages here
          switch (msg.Method) {
            case EStratumMethodTy::ESubscribe :
              connection->Instance->onStratumSubscribe(connection, msg);
              break;
            case EStratumMethodTy::EAuthorize : {
              result = connection->Instance->onStratumAuthorize(connection, msg);
              connection->Instance->stratumSendTarget(connection);
              CWork *currentWork = data.WorkStorage.currentWork();
              if (result && currentWork) {
                connection->Instance->stratumSendWork(connection, currentWork, time(nullptr));
              }
              break;
            }
            case EStratumMethodTy::EMiningConfigure :
              connection->Instance->onStratumMiningConfigure(connection, msg);
              break;
            case EStratumMethodTy::EMiningSuggestDifficulty :
              connection->Instance->onStratumMiningSuggestDifficulty(connection, msg);
              break;
            case EStratumMethodTy::EExtraNonceSubscribe :
              connection->Instance->onStratumExtraNonceSubscribe(connection, msg);
              break;
            case EStratumMethodTy::ESubmit :
              connection->Instance->onStratumSubmit(connection, msg);
              break;
            case EStratumMethodTy::EMultiVersion :
              connection->Instance->onStratumMultiVersion(connection, msg);
              break;
            case EStratumMethodTy::ESubmitHashrate :
              connection->Instance->onStratumSubmitHashrate(connection, msg);
              break;
            default : {
              // unknown method
              struct in_addr addr;
              addr.s_addr = connection->Address.ipv4;
              std::string msg(p, stratumMsgSize);
              LOG_F(ERROR, "%s: unknown stratum method received from %s" , connection->Instance->Name_.c_str(), inet_ntoa(addr));
              LOG_F(ERROR, " * message text: %s", msg.c_str());
              break;
            }
          }

          break;
        case EStratumDecodeStatusTy::EStratumStatusJsonError : {
          std::string msg(p, stratumMsgSize);
          LOG_F(ERROR, "%s(%s): JsonError %s", connection->Instance->Name_.c_str(), connection->AddressHr.c_str(), msg.c_str());
          result = false;
          break;
        }
        case EStratumDecodeStatusTy::EStratumStatusFormatError : {
          std::string msg(p, stratumMsgSize);
          LOG_F(ERROR, "%s(%s): FormatError %s", connection->Instance->Name_.c_str(), connection->AddressHr.c_str(), msg.c_str());
          result = false;
          break;
        }
        default :
          break;
      }

      if (!result) {
        connection->close();
        return;
      }

      p = nextMsgPos + 1;
    }

    // move tail to begin of buffer
    if (p != e) {
      connection->MsgTailSize = e-p;
      if (connection->MsgTailSize >= sizeof(connection->Buffer)) {
        struct in_addr addr;
        addr.s_addr = connection->Address.ipv4;
        LOG_F(ERROR, "%s: too long stratum message from %s", connection->Instance->Name_.c_str(), inet_ntoa(addr));
        connection->close();
        return;
      }

      memmove(connection->Buffer, p, e-p);
    } else {
      connection->MsgTailSize = 0;
    }

    if (connection->Active)
      aioRead(connection->Socket, connection->Buffer + connection->MsgTailSize, sizeof(connection->Buffer) - connection->MsgTailSize, afNone, 0, reinterpret_cast<aioCb*>(readCb), connection);
  }

  void rttTimerCb() {
    ThreadData &data = Data_[GetLocalThreadId()];
    size_t backendsNum = data.WorkStorage.backendsNum();
    for (size_t i = 0; i < backendsNum; i++) {
      const auto &share = data.WorkStorage.pendingShare(i);
      if (share.HasShare) {
        sharePendingCheck(i,
                          share.User,
                          share.WorkerName,
                          share.MajorJobId,
                          share.StratumDifficulty,
                          share.WorkerConfig,
                          share.Msg);
      }
    }
  }

  std::string workName(CWork *work) {
    std::string name;
    for (size_t i = 0; i < work->backendsNum(); i++) {
      if (work->backend(i)) {
        if (!name.empty())
          name.push_back('+');
        name.append(work->backend(i)->getCoinInfo().Name);
      }
    }

    return name;
  }

private:
  unsigned CurrentThreadId_;
  std::unique_ptr<ThreadData[]> Data_;
  std::string Name_ = "stratum";
  CMiningConfig MiningCfg_;
  double ConstantShareDiff_;

  // Profit switcher section
  bool ProfitSwitcherEnabled_ = false;

  // ASIC boost 'overt' data
  uint32_t VersionMask_ = 0x1FFFE000;
};
