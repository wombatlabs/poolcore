#pragma once

#include <string>
#include "rapidjson/document.h"

enum EErrorType {
  EOk = 0,
  ENotExists,
  ETypeMismatch
};

struct CPoolFrontendConfig {
  bool IsMaster;
  unsigned HttpPort;
  unsigned WorkerThreadsNum;
  unsigned HttpThreadsNum;
  std::string AdminPasswordHash;
  std::string ObserverPasswordHash;
  std::string DbPath;
  std::string PoolName;
  std::string PoolHostProtocol;
  std::string PoolHostAddress;
  std::string PoolActivateLinkPrefix;
  std::string PoolChangePasswordLinkPrefix;
  std::string PoolActivate2faLinkPrefix;
  std::string PoolDeactivate2faLinkPrefix;

  bool SmtpEnabled;
  std::string SmtpServer;
  std::string SmtpLogin;
  std::string SmtpPassword;
  std::string SmtpSenderAddress;
  bool SmtpUseSmtps;
  bool SmtpUseStartTls;

  bool load(rapidjson::Document &document, std::string &errorDescription);
};
