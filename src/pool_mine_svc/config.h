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
  uint32_t Weight;
};

struct CCoinConfig {
  std::string Name;
  std::vector<CNodeConfig> GetWorkNodes;
  std::vector<CMiningAddressConfig> MiningAddresses;
  std::string CoinbaseMsg;

  void load(const rapidjson::Value &value, std::string &errorDescription, EErrorType *error);
};

struct CConfig {
  std::string Name;
  std::string UniqueId;
  std::string DbPath;
  std::string Type;
  std::string Protocol;
  std::vector<std::string> Backends;
  unsigned Port;
  double StratumShareDiff;
  unsigned WorkerThreadsNum;
  std::vector<CCoinConfig> Coins;

  rapidjson::Value InstanceConfig;

  bool load(rapidjson::Document &value, std::string &errorDescription);
};
