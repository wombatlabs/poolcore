#pragma once

#include <string>
#include <vector>
#include "rapidjson/document.h"

enum EErrorType {
  EOk = 0,
  ENotExists,
  ETypeMismatch
};

struct CNodeConfig {
  std::string Type;
  std::string Address;
  std::string Login;
  std::string Password;
  bool LongPollEnabled;

  void load(const rapidjson::Value &value, const std::string &path, std::string &errorDescription, EErrorType *error);
};

struct CMiningAddressConfig {
  std::string Address;
  std::string PrivateKey;
  uint32_t Weight;
};

struct CCoinConfig {
  std::string Name;
  std::string DbPath;
  std::vector<CNodeConfig> GetWorkNodes;
  std::vector<CNodeConfig> RPCNodes;
  unsigned RequiredConfirmations;
  std::string DefaultPayoutThreshold;
  std::string MinimalAllowedPayout;
  unsigned KeepRoundTime;
  unsigned KeepStatsTime;
  unsigned ConfirmationsCheckInterval;
  unsigned PayoutInterval;
  unsigned BalanceCheckInterval;
  unsigned StatisticCheckInterval;
  unsigned ShareTarget;
  unsigned StratumWorkLifeTime;
  std::vector<CMiningAddressConfig> MiningAddresses;
  std::string CoinbaseMsg;
  double ProfitSwitchCoeff;
  std::string PoolZAddr;
  std::string PoolTAddr;

  bool load(const rapidjson::Value &value, std::string &errorDescription);
};

