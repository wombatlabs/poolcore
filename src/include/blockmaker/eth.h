#pragma once

#include "stratumWork.h"
#include "poolcommon/arith_uint256.h"
#include "poolinstances/stratumMsg.h"
#include "poolcommon/jsonSerializer.h"
#include "rapidjson/document.h"
#include <openssl/rand.h>

namespace ETH {

struct BlockSubmitData {
  char Nonce[16+2+1];
  char HeaderHash[64+2+1];
  char MixHash[64+2+1];
};

class Proto {
public:
  using BlockHashTy = uint256;
  using AddressTy = uint256;
  static bool decodeHumanReadableAddress(const std::string&, const std::vector<uint8_t>&, AddressTy&) { return true; }
};

class Stratum {
public:
  struct StratumMiningSubscribe {
    std::string minerUserAgent;
    std::string StratumVersion;
  };

  struct StratumSubmit {
    std::string WorkerName;
    std::string JobId;
    uint64_t Nonce;
    // TODO: remove
    std::optional<uint32_t> VersionBits;
  };

  struct StratumMessage {
    int64_t IntegerId;
    std::string StringId;
    EStratumMethodTy Method;

    StratumMiningSubscribe Subscribe;
    StratumAuthorize Authorize;
    StratumMiningConfigure MiningConfigure;
    StratumSubmit Submit;

    EStratumDecodeStatusTy decodeStratumMessage(const char *in, size_t size);

    void addId(JSON::Object &object) {
      if (!StringId.empty())
        object.addString("id", StringId);
      else
        object.addInt("id", IntegerId);
    }
  };

  struct MiningConfig {
    unsigned FixedExtraNonceSize = 3;

    void initialize(rapidjson::Value &instanceCfg) {
      if (instanceCfg.HasMember("fixedExtraNonceSize") && instanceCfg["fixedExtraNonceSize"].IsUint())
        FixedExtraNonceSize = instanceCfg["fixedExtraNonceSize"].GetUint();
    }
  };

  static void workerConfigInitialize(CWorkerConfig &workerCfg, ThreadConfig &threadCfg) {
    // Set fixed part of extra nonce
    workerCfg.ExtraNonceFixed = threadCfg.ExtraNonceCurrent;

    // Set session names
    uint8_t sessionId[16];
    {
      RAND_bytes(sessionId, sizeof(sessionId));
      workerCfg.NotifySession.resize(sizeof(sessionId)*2);
      bin2hexLowerCase(sessionId, workerCfg.NotifySession.data(), sizeof(sessionId));
    }

    // Update thread config
    threadCfg.ExtraNonceCurrent += threadCfg.ThreadsNum;
  }

  static void workerConfigSetupVersionRolling(CWorkerConfig&, uint32_t) {}

  static void workerConfigOnSubscribe(CWorkerConfig &workerCfg, MiningConfig &miningCfg, StratumMessage &msg, xmstream &out, std::string &subscribeInfo) {
    // Response format
    // {"id": 1, "result": [["mining.notify", "ae6812eb4cd7735a302a8a9dd95cf71f", "EthereumStratum/1.0.0"], "080c"],"error": null}

    {
      JSON::Object object(out);
      if (!msg.StringId.empty())
        object.addString("id", msg.StringId);
      else
        object.addInt("id", msg.IntegerId);
      object.addField("result");
      {
        JSON::Array resultValue(out);
        resultValue.addField();
        {
          JSON::Array notifySession(out);
          notifySession.addString("mining.notify");
          notifySession.addString(workerCfg.NotifySession);
          notifySession.addString("EthereumStratum/1.0.0");
        }
        // Unique extra nonce
        resultValue.addString(writeHexBE(workerCfg.ExtraNonceFixed, miningCfg.FixedExtraNonceSize));
      }
      object.addNull("error");
    }

    out.write('\n');
    subscribeInfo = std::to_string(workerCfg.ExtraNonceFixed);
  }

  using CSingleWork = StratumSingleWork<Proto::BlockHashTy, MiningConfig, StratumMessage>;

  class Work : public CSingleWork {
  public:
    Work(int64_t stratumWorkId, uint64_t uniqueWorkId, PoolBackend *backend, size_t backendIdx, const MiningConfig &miningCfg, const std::vector<uint8_t>&, const std::string&) :
      CSingleWork(stratumWorkId, uniqueWorkId, backend, backendIdx, miningCfg) {
      Initialized_ = true;
    }

    virtual Proto::BlockHashTy shareHash() override {
      uint256 hash;
      memcpy(hash.begin(), FinalHash_.begin(), 32);
      return hash;
    }

    virtual std::string blockHash(size_t) override {
      uint256 hash(MixHash_);
      std::reverse(hash.begin(), hash.end());
      return hash.ToString();
    }

    virtual double expectedWork(size_t) override {
      // TODO: implement
      return 0.0;
    }

    virtual bool ready() override {
      return true;
    }

    virtual void buildBlock(size_t, xmstream &blockHexData) override;

    virtual void mutate() override {}

    virtual CCheckStatus checkConsensus(size_t) override;

    virtual bool hasRtt(size_t) override { return false; }

    virtual void buildNotifyMessage(bool resetPreviousWork) override;

    virtual bool loadFromTemplate(CBlockTemplate &blockTemplate, const std::string &ticker, std::string &error) override;

    virtual bool prepareForSubmit(const CWorkerConfig &workerCfg, const StratumMessage&msg) override;

    virtual double getAbstractProfitValue(size_t, double, double) override {
      // TODO: calculate real profit value
      return 0.00000001;
    }

  private:
    std::string HeaderHashHex_;
    std::string SeedHashHex_;
    uint256 HeaderHash_;
    arith_uint256 Target_;
    uint64_t Nonce_ = 0;
    arith_uint256 FinalHash_;
    uint256 MixHash_;
    intrusive_ptr<EthashDagWrapper> DagFile_;
  };

  static constexpr bool MergedMiningSupport = false;
  static bool isMainBackend(const std::string&) { return true; }
  static bool keepOldWorkForBackend(const std::string&) { return false; }

  static void buildSendTargetMessage(xmstream &stream, double difficulty) {
    JSON::Object object(stream);
    object.addString("method", "mining.set_difficulty");
    object.addNull("id");
    object.addField("params");
    {
      JSON::Array params(stream);
      params.addDouble(difficulty);
    }
  }

  using SecondWork = StratumSingleWorkEmpty<Proto::BlockHashTy, MiningConfig, StratumMessage>;
  using MergedWork = StratumMergedWorkEmpty<Proto::BlockHashTy, MiningConfig, StratumMessage>;
};

struct X {
  using Proto = ETH::Proto;
  using Stratum = ETH::Stratum;
};
}
