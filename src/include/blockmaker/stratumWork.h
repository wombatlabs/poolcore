#pragma once

#include "poolcore/blockTemplate.h"
#include "poolinstances/stratumMsg.h"
#include "poolcommon/uint256.h"
#include "p2putils/xmstream.h"
#include <string>
#include <vector>

struct ThreadConfig {
  uint64_t ExtraNonceCurrent;
  unsigned ThreadsNum;
  void initialize(unsigned instanceId, unsigned instancesNum) {
    ExtraNonceCurrent = instanceId;
    ThreadsNum = instancesNum;
  }
};

struct CMiningConfig {
  unsigned FixedExtraNonceSize;
  unsigned MutableExtraNonceSize;
  unsigned TxNumLimit;
};

// Worker config contains set of fields for all supported stratums
struct CWorkerConfig {
  std::string SetDifficultySession;
  std::string NotifySession;
  uint64_t ExtraNonceFixed;
  // SHA-256 only ASIC-boost fields
  bool AsicBoostEnabled = false;
  uint32_t VersionMask = 0;
};

struct CCheckStatus {
  bool IsBlock = false;
  double ShareDiff = 0.0;
  // For XEC rtt
  bool IsPendingBlock = false;

};

class StratumMergedWork;
class PoolBackend;

class StratumWork {
public:
  StratumWork(uint64_t stratumId, const CMiningConfig &miningCfg) : StratumId_(stratumId), MiningCfg_(miningCfg) {}
  virtual ~StratumWork() {}

  bool initialized() { return Initialized_; }
  virtual size_t backendsNum() = 0;
  virtual uint256 shareHash() = 0;
  virtual std::string blockHash(size_t workIdx) = 0;
  virtual PoolBackend *backend(size_t workIdx) = 0;
  virtual size_t backendId(size_t workIdx) = 0;
  virtual uint64_t height(size_t workIdx) = 0;
  virtual size_t txNum(size_t workIdx) = 0;
  virtual int64_t blockReward(size_t workIdx) = 0;
  virtual double expectedWork(size_t workIdx) = 0;
  virtual void buildBlock(size_t workIdx, xmstream &stream) = 0;
  virtual bool ready() = 0;
  virtual void mutate() = 0;
  virtual CCheckStatus checkConsensus(size_t workIdx) = 0;
  virtual void buildNotifyMessage(bool resetPreviousWork) = 0;
  virtual bool prepareForSubmit(const CWorkerConfig &workerCfg, const CStratumMessage &msg) = 0;
  virtual double getAbstractProfitValue(size_t workIdx, double price, double coeff) = 0;
  virtual bool hasRtt(size_t workIdx) = 0;

  xmstream &notifyMessage() { return NotifyMessage_; }
  int64_t stratumId() const { return StratumId_; }
  void setStratumId(int64_t stratumId) { StratumId_ = stratumId; }

public:
  bool Initialized_ = false;
  int64_t StratumId_ = 0;
  unsigned SendCounter_ = 0;
  CMiningConfig MiningCfg_;
  xmstream NotifyMessage_;
};

class StratumSingleWork : public StratumWork {
public:
  StratumSingleWork(int64_t stratumWorkId, uint64_t uniqueWorkId, PoolBackend *backend, size_t backendId, const CMiningConfig &miningCfg) :
      StratumWork(stratumWorkId, miningCfg), UniqueWorkId_(uniqueWorkId), Backend_(backend), BackendId_(backendId) {}

  virtual size_t backendsNum() final { return 1; }
  virtual PoolBackend *backend(size_t) final { return Backend_; }
  virtual size_t backendId(size_t) final { return BackendId_; }
  virtual uint64_t height(size_t) final { return Height_; }
  virtual size_t txNum(size_t) final { return TxNum_; }
  virtual int64_t blockReward(size_t) final { return BlockReward_; }

  virtual bool loadFromTemplate(CBlockTemplate &blockTemplate, const std::string &ticker, std::string &error) = 0;

  virtual ~StratumSingleWork();

  uint64_t uniqueWorkId() { return UniqueWorkId_; }

  void addLink(StratumMergedWork *mergedWork) {
    LinkedWorks_.push_back(mergedWork);
  }

  void clearLinks() {
    LinkedWorks_.clear();
  }

protected:
  uint64_t UniqueWorkId_ = 0;
  PoolBackend *Backend_ = nullptr;
  size_t BackendId_ = 0;
  std::vector<StratumMergedWork*> LinkedWorks_;
  uint64_t Height_ = 0;
  size_t TxNum_ = 0;
  int64_t BlockReward_ = 0;
};

class StratumMergedWork : public StratumWork {
public:
  StratumMergedWork(uint64_t stratumWorkId,
                    StratumSingleWork *first,
                    StratumSingleWork *second,
                    const CMiningConfig &miningCfg) : StratumWork(stratumWorkId, miningCfg) {
    Works_[0] = first;
    Works_[1] = second;
    WorkId_[0] = first->backendId(0);
    WorkId_[1] = second->backendId(0);
    first->addLink(this);
    second->addLink(this);
    this->Initialized_ = true;
  }

  virtual ~StratumMergedWork() {}

  virtual size_t backendsNum() final { return 2; }
  virtual PoolBackend *backend(size_t workIdx) final { return Works_[workIdx] ? Works_[workIdx]->backend(0) : nullptr; }
  virtual size_t backendId(size_t workIdx) final { return WorkId_[workIdx]; }
  virtual uint64_t height(size_t workIdx) final { return Works_[workIdx]->height(0); }
  virtual size_t txNum(size_t workIdx) final { return Works_[workIdx]->txNum(0); }
  virtual int64_t blockReward(size_t workIdx) final { return Works_[workIdx]->blockReward(0); }
  virtual double expectedWork(size_t workIdx) final { return Works_[workIdx]->expectedWork(0); }
  virtual bool ready() final { return true; }
  virtual double getAbstractProfitValue(size_t workIdx, double price, double coeff) final { return Works_[workIdx]->getAbstractProfitValue(0, price, coeff); }
  virtual bool hasRtt(size_t workIdx) final { return Works_[workIdx]->hasRtt(0); }

  void removeLink(StratumSingleWork *work) {
    if (Works_[0] == work)
      Works_[0] = nullptr;
    if (Works_[1] == work)
      Works_[1] = nullptr;
  }

  bool empty() { return Works_[0] == nullptr && Works_[1] == nullptr; }

protected:
  StratumSingleWork *Works_[2] = {nullptr, nullptr};
  size_t WorkId_[2] = {std::numeric_limits<size_t>::max(), std::numeric_limits<size_t>::max()};
};

class StratumSingleWorkEmpty : public StratumSingleWork {
public:
  StratumSingleWorkEmpty(int64_t stratumWorkId,
                         uint64_t uniqueWorkId,
                         PoolBackend *backend,
                         size_t backendId,
                         const CMiningConfig &miningCfg,
                         const std::vector<uint8_t>&,
                         const std::string&) : StratumSingleWork(stratumWorkId, uniqueWorkId, backend, backendId, miningCfg) {}
  virtual uint256 shareHash() final { return uint256(); }
  virtual std::string blockHash(size_t) final { return std::string(); }
  virtual double expectedWork(size_t) final { return 0.0; }
  virtual void buildBlock(size_t, xmstream&) final {}
  virtual bool ready() final { return false; }
  virtual void mutate() final {}
  virtual CCheckStatus checkConsensus(size_t) final { return CCheckStatus(); }
  virtual void buildNotifyMessage(bool) final {}
  virtual bool prepareForSubmit(const CWorkerConfig&, const CStratumMessage&) final { return false; }
  virtual bool loadFromTemplate(CBlockTemplate&, const std::string&, std::string&) final { return false; }
  virtual double getAbstractProfitValue(size_t, double, double) final { return 0.0; }
  virtual bool resetNotRecommended() final { return false; }
  virtual bool hasRtt(size_t) final { return false; }
};

class StratumMergedWorkEmpty : public StratumMergedWork {
public:
  StratumMergedWorkEmpty(uint64_t stratumWorkId,
                         StratumSingleWork *first,
                         StratumSingleWork *second,
                         CMiningConfig &cfg) : StratumMergedWork(stratumWorkId, first, second, cfg) {}
  virtual uint256 shareHash() final { return uint256(); }
  virtual std::string blockHash(size_t) final { return std::string(); }
  virtual void buildBlock(size_t, xmstream&) final {}
  virtual void mutate() final {}
  virtual void buildNotifyMessage(bool) final {}
  virtual bool prepareForSubmit(const CWorkerConfig&, const CStratumMessage&) final { return false; }
  virtual CCheckStatus checkConsensus(size_t) final { return CCheckStatus(); }
};
