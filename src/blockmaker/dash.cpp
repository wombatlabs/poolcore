
#include "blockmaker/dash.h"
#include "blockmaker/x11.h"
#include "poolcommon/hex.h"
#include "rapidjson/document.h"

namespace DASH {

DashCoin::DashCoin() {}

bool DashCoin::parseBlockTemplate(const rapidjson::Document &doc, BlockHeader &header) {
  if (!doc.IsObject())
    return false;

  const auto &o = doc;

  if (!o.HasMember("version") || !o.HasMember("previousblockhash") ||
      !o.HasMember("merkleroot") || !o.HasMember("bits") || !o.HasMember("curtime") || !o.HasMember("nonce"))
    return false;

  header.nVersion = o["version"].GetInt();
  header.nType = o.HasMember("type") ? o["type"].GetUint() : 0;
  header.hashPrevBlock.SetHex(o["previousblockhash"].GetString());
  header.hashMerkleRoot.SetHex(o["merkleroot"].GetString());
  header.nBits = std::stoul(o["bits"].GetString(), nullptr, 16);
  header.nTime = o["curtime"].GetUint();
  header.nNonce = o["nonce"].GetUint();

  if (o.HasMember("default_witness_commitment"))
    header.hashStateRoot.SetNull();  // Optional, Dash doesn't use SegWit
  if (o.HasMember("hashUTXORoot"))
    header.hashUTXORoot.SetHex(o["hashUTXORoot"].GetString());

  if (o.HasMember("extraPayload") && o["extraPayload"].IsString()) {
    const char *hexPayload = o["extraPayload"].GetString();
    size_t len = strlen(hexPayload);
    header.extraPayload.resize(len / 2);
    hex2bin(hexPayload, len, header.extraPayload.data());
  }

  return true;
}

uint256 getBlockHash(const Proto::BlockHeader &header) {
  xmstream stream;
  DASH::Proto::BlockHeader h = header;

  // Serialize the header
  BTC::serialize(stream, h.nVersion);
  BTC::serialize(stream, h.nType);
  BTC::serialize(stream, h.hashPrevBlock);
  BTC::serialize(stream, h.hashMerkleRoot);
  BTC::serialize(stream, h.nTime);
  BTC::serialize(stream, h.nBits);
  BTC::serialize(stream, h.nNonce);

  if (!h.extraPayload.empty())
    BTC::serialize(stream, h.extraPayload);

  uint8_t hash[64];
  x11_hash((const uint8_t*)stream.data(), stream.size(), hash);
  return uint256(hash);
}

} // namespace DASH
