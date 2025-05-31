namespace FB {
  class Stratum {
  public:
    // 1) Accessors to the underlying WorkTy pointers:
    BTC::Stratum::Work  *btcWork() { return static_cast<BTC::Stratum::Work*>(Works_[0].Work); }
    FbWork              *fbWork(unsigned index) { return static_cast<FbWork*>(Works_[index+1].Work); }

    // 2) Merged‐mining support:
    static std::vector<int> buildChainMap(std::vector<StratumSingleWork*> &secondary, uint32_t &nonce, unsigned &virtualHashesNum);
    static constexpr bool MergedMiningSupport = true;
    // … plus decodeStratumMessage, miningConfigInitialize, workerConfigInitialize, etc. (copied from DOGE’s pattern)
    // …

    class MergedWork : public StratumMergedWork {
    public:
        MergedWork(uint64_t stratumWorkId,
                   StratumSingleWork *first,
                   std::vector<StratumSingleWork*> &second,
                   std::vector<int> &mmChainId,
                   uint32_t mmNonce,
                   unsigned virtualHashesNum,
                   const CMiningConfig &miningCfg);

        bool prepareForSubmit(const CWorkerConfig &workerCfg, const CStratumMessage &msg) override;

        // internal fields (parallel to DOGE/H):
        BTC::Proto::BlockHeader          BTCHeader_;
        std::vector<uint256>             BTCMerklePath_;
        BTC::Proto::CheckConsensusCtx    BTCConsensusCtx_;
        BTC::CoinbaseTx                  BTCLegacy_;
        BTC::CoinbaseTx                  BTCWitness_;

        std::vector<FB::Proto::BlockHeader> fbHeaders_;
        std::vector<BTC::CoinbaseTx>         fbLegacy_;
        std::vector<BTC::CoinbaseTx>         fbWitness_;
        std::vector<uint256>                 fbHeaderHashes_;
        std::vector<int>                     fbWorkMap_;
        FB::Proto::CheckConsensusCtx         fbConsensusCtx_;
    };

    // plus any other necessary methods:
    static double expectedWork(const Proto::BlockHeader &header, const CheckConsensusCtx &ctx);
    static void buildNotifyMessage(xmstream &stream, 
                                   const Proto::BlockHeader &header, 
                                   uint32_t coinbaseSize, 
                                   int &extraNonce, 
                                   const std::vector<base_blob<256>> &merkleBranch, 
                                   const CMiningConfig &miningCfg, 
                                   bool segwitEnabled, 
                                   xmstream &targetOut);
    static void buildSendTargetMessage(xmstream &stream, double shareDiff);
    static Work *newPrimaryWork(int64_t stratumId,
                                PoolBackend *backend,
                                size_t backendIdx,
                                const CMiningConfig &miningCfg,
                                const std::vector<uint8_t> &miningAddress,
                                const std::string &coinbaseMessage,
                                CBlockTemplate &blockTemplate,
                                std::string &error);
    static Work *newSecondaryWork(int64_t stratumId,
                                  PoolBackend *backend,
                                  size_t backendIdx,
                                  const CMiningConfig &miningCfg,
                                  const std::vector<uint8_t> &miningAddress,
                                  const std::string &coinbaseMessage,
                                  CBlockTemplate &blockTemplate,
                                  std::string &error);
  };

  // And the usual X struct for serialization:
  struct X {
    using Proto   = FB::Proto;
    using Stratum = FB::Stratum;
    template<typename T> static inline void serialize(xmstream &s, const T &d)   { BTC::Io<T>::serialize(s, d); }
    template<typename T> static inline void unserialize(xmstream &s, T &d)       { BTC::Io<T>::unserialize(s, d); }
  };
}
