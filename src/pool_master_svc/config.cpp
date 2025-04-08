#include "config.h"

static inline void setErrorDescription(EErrorType error, EErrorType *errorAcc, const std::string &place, const char *name, const char *requiredType, std::string &errorDescription)
{
  *errorAcc = error;
  if (error == ENotExists) {
    errorDescription = (std::string)"Required parameter '" + name + "' does not exists at " + place;
  } else if (error == ETypeMismatch) {
    errorDescription = (std::string)"Type mismatch: parameter '" + place + " -> " + name + "' must be a " + requiredType;
  }
}

static inline void jsonParseString(const rapidjson::Value &value, const char *name, std::string &out, EErrorType *validAcc, const std::string &place, std::string &errorDescription) {
  if (*validAcc != EOk)
    return;

  if (value.HasMember(name)) {
    if (value[name].IsString())
      out = value[name].GetString();
    else
      setErrorDescription(ETypeMismatch, validAcc, place, name, "string", errorDescription);
  } else {
    setErrorDescription(ENotExists, validAcc, place, name, "string", errorDescription);
  }
}

static inline void jsonParseString(const rapidjson::Value &value, const char *name, std::string &out, const std::string &defaultValue, EErrorType *validAcc, const std::string &place, std::string &errorDescription) {
  if (*validAcc != EOk)
    return;

  if (value.HasMember(name)) {
    if (value[name].IsString())
      out = value[name].GetString();
    else
      setErrorDescription(ETypeMismatch, validAcc, place, name, "string", errorDescription);
  } else {
    out = defaultValue;
  }
}

static inline void jsonParseBoolean(const rapidjson::Value &value, const char *name, bool *out, EErrorType *validAcc, const std::string &place, std::string &errorDescription) {
  if (*validAcc != EOk)
    return;

  if (value.HasMember(name)) {
    if (value[name].IsBool())
      *out = value[name].GetBool();
    else
      setErrorDescription(ETypeMismatch, validAcc, place, name, "boolean", errorDescription);
  } else {
    setErrorDescription(ENotExists, validAcc, place, name, "boolean", errorDescription);
  }
}

static inline void jsonParseBoolean(const rapidjson::Value &value, const char *name, bool *out, bool defaultValue, EErrorType *validAcc, const std::string &place, std::string &errorDescription) {
  if (*validAcc != EOk)
    return;

  if (value.HasMember(name)) {
    if (value[name].IsBool())
      *out = value[name].GetBool();
    else
      setErrorDescription(ETypeMismatch, validAcc, place, name, "boolean", errorDescription);
  } else {
    *out = defaultValue;
  }
}

static inline void jsonParseUInt(const rapidjson::Value &value, const char *name, unsigned *out, EErrorType *validAcc, const std::string &place, std::string &errorDescription) {
  if (*validAcc != EOk)
    return;

  if (value.HasMember(name)) {
    if (value[name].IsUint())
      *out = value[name].GetUint();
    else
      setErrorDescription(ETypeMismatch, validAcc, place, name, "unsigned integer", errorDescription);
  } else {
    setErrorDescription(ENotExists, validAcc, place, name, "unsigned integer", errorDescription);
  }
}

static inline void jsonParseUInt(const rapidjson::Value &value, const char *name, unsigned *out, unsigned defaultValue, EErrorType *validAcc, const std::string &place, std::string &errorDescription) {
  if (*validAcc != EOk)
    return;

  if (value.HasMember(name)) {
    if (value[name].IsUint())
      *out = value[name].GetUint();
    else
      setErrorDescription(ETypeMismatch, validAcc, place, name, "unsigned integer", errorDescription);
  } else {
    *out = defaultValue;
  }
}

bool CPoolFrontendConfig::load(rapidjson::Document &document, std::string &errorDescription)
{
  EErrorType error = EOk;

  // Frontend (object)
  if (!document.HasMember("poolfrontend")) {
    setErrorDescription(ENotExists, &error, ".", "poolfrontend", "array of objects", errorDescription);
    return false;
  }
  if (!document["poolfrontend"].IsObject()) {
    setErrorDescription(ETypeMismatch, &error, ".", "poolfrontend", "array of objects", errorDescription);
    return false;
  }

  {
    const char *localPath = "poolfrontend";
    rapidjson::Value &object = document["poolfrontend"];
    jsonParseBoolean(object, "isMaster", &IsMaster, &error, localPath, errorDescription);
    jsonParseUInt(object, "httpPort", &HttpPort, &error, localPath, errorDescription);
    jsonParseUInt(object, "workerThreadsNum", &WorkerThreadsNum, 0, &error, localPath, errorDescription);
    jsonParseUInt(object, "httpThreadsNum", &HttpThreadsNum, 0, &error, localPath, errorDescription);
    jsonParseString(object, "adminPasswordHash", AdminPasswordHash, "", &error, localPath, errorDescription);
    jsonParseString(object, "observerPasswordHash", ObserverPasswordHash, "", &error, localPath, errorDescription);
    jsonParseString(object, "dbPath", DbPath, &error, localPath, errorDescription);
    jsonParseString(object, "poolName", PoolName, &error, localPath, errorDescription);
    jsonParseString(object, "poolHostProtocol", PoolHostProtocol, &error, localPath, errorDescription);
    jsonParseString(object, "poolHostAddress", PoolHostAddress, &error, localPath, errorDescription);
    jsonParseString(object, "poolActivateLinkPrefix", PoolActivateLinkPrefix, &error, localPath, errorDescription);
    jsonParseString(object, "poolChangePasswordLinkPrefix", PoolChangePasswordLinkPrefix, &error, localPath, errorDescription);
    jsonParseString(object, "poolActivate2faLinkPrefix", PoolActivate2faLinkPrefix, &error, localPath, errorDescription);
    jsonParseString(object, "poolDeactivate2faLinkPrefix", PoolDeactivate2faLinkPrefix, &error, localPath, errorDescription);
    jsonParseBoolean(object, "smtpEnabled", &SmtpEnabled, &error, localPath, errorDescription);
    jsonParseString(object, "smtpServer", SmtpServer, &error, localPath, errorDescription);
    jsonParseString(object, "smtpLogin", SmtpLogin, &error, localPath, errorDescription);
    jsonParseString(object, "smtpPassword", SmtpPassword, &error, localPath, errorDescription);
    jsonParseString(object, "smtpSenderAddress", SmtpSenderAddress, &error, localPath, errorDescription);
    jsonParseBoolean(object, "smtpUseSmtps", &SmtpUseSmtps, false, &error, localPath, errorDescription);
    jsonParseBoolean(object, "smtpUseStartTLS", &SmtpUseStartTls, true, &error, localPath, errorDescription);
  }

  return error == EOk;
}
