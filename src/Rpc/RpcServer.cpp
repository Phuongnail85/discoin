// Copyright (c) 2011-2016 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "RpcServer.h"

#include <future>
#include <unordered_map>

// CryptoNote
#include "Common/StringTools.h"
#include "CryptoNoteCore/CryptoNoteTools.h"
#include "CryptoNoteCore/Core.h"
#include "CryptoNoteCore/IBlock.h"
#include "CryptoNoteCore/Miner.h"
#include "CryptoNoteCore/TransactionExtra.h"

#include "CryptoNoteProtocol/ICryptoNoteProtocolQuery.h"

#include "P2p/NetNode.h"

#include "CoreRpcServerErrorCodes.h"
#include "JsonRpc.h"

#undef ERROR

using namespace Logging;
using namespace Crypto;
using namespace Common;

namespace CryptoNote {

namespace {

template <typename Command>
RpcServer::HandlerFunction binMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const HttpRequest& request, HttpResponse& response) {

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromBinaryKeyValue(static_cast<typename Command::request&>(req), request.getBody())) {
      return false;
    }

    bool result = (obj->*handler)(req, res);
    response.setBody(storeToBinaryKeyValue(res.data()));
    return result;
  };
}

template <typename Command>
RpcServer::HandlerFunction jsonMethod(bool (RpcServer::*handler)(typename Command::request const&, typename Command::response&)) {
  return [handler](RpcServer* obj, const HttpRequest& request, HttpResponse& response) {
    RpcServer::addJsonHeaders(response);

    boost::value_initialized<typename Command::request> req;
    boost::value_initialized<typename Command::response> res;

    if (!loadFromJson(static_cast<typename Command::request&>(req), request.getBody())) {
      return false;
    }

    bool result = (obj->*handler)(req, res);
    response.setBody(storeToJson(res.data()));
    return result;
  };
}

}

std::unordered_map<std::string, RpcServer::RpcHandler<RpcServer::HandlerFunction>> RpcServer::s_handlers = {

  // binary handlers
  { "/getblocks.bin", { binMethod<COMMAND_RPC_GET_BLOCKS_FAST>(&RpcServer::on_get_blocks), false } },
  { "/queryblocks.bin", { binMethod<COMMAND_RPC_QUERY_BLOCKS>(&RpcServer::on_query_blocks), false } },
  { "/queryblockslite.bin", { binMethod<COMMAND_RPC_QUERY_BLOCKS_LITE>(&RpcServer::on_query_blocks_lite), false } },
  { "/get_o_indexes.bin", { binMethod<COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES>(&RpcServer::on_get_indexes), false } },
  { "/getrandom_outs.bin", { binMethod<COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS>(&RpcServer::on_get_random_outs), false } },
  { "/get_pool_changes.bin", { binMethod<COMMAND_RPC_GET_POOL_CHANGES>(&RpcServer::onGetPoolChanges), false } },
  { "/get_pool_changes_lite.bin", { binMethod<COMMAND_RPC_GET_POOL_CHANGES_LITE>(&RpcServer::onGetPoolChangesLite), false } },

  // json handlers
  { "/getinfo", { jsonMethod<COMMAND_RPC_GET_INFO>(&RpcServer::on_get_info), true } },
  { "/getheight", { jsonMethod<COMMAND_RPC_GET_HEIGHT>(&RpcServer::on_get_height), true } },
  { "/gettransactions", { jsonMethod<COMMAND_RPC_GET_TRANSACTIONS>(&RpcServer::on_get_transactions), false } },
  { "/sendrawtransaction", { jsonMethod<COMMAND_RPC_SEND_RAW_TX>(&RpcServer::on_send_raw_tx), false } },
  { "/start_mining", { jsonMethod<COMMAND_RPC_START_MINING>(&RpcServer::on_start_mining), false } },
  { "/stop_mining", { jsonMethod<COMMAND_RPC_STOP_MINING>(&RpcServer::on_stop_mining), false } },
  { "/stop_daemon", { jsonMethod<COMMAND_RPC_STOP_DAEMON>(&RpcServer::on_stop_daemon), true } },

  // json rpc
  { "/json_rpc", { std::bind(&RpcServer::processJsonRpcRequest, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3), true } }
};

RpcServer::RpcServer(System::Dispatcher& dispatcher, Logging::ILogger& log, core& c, NodeServer& p2p, const ICryptoNoteProtocolQuery& protocolQuery) :
  HttpServer(dispatcher, log), logger(log, "RpcServer"), m_core(c), m_p2p(p2p), m_protocolQuery(protocolQuery) {
}

void RpcServer::processRequest(const HttpRequest& request, HttpResponse& response) {
  auto url = request.getUrl();

  auto it = s_handlers.find(url);
  if (it == s_handlers.end()) {
    response.setStatus(HttpResponse::STATUS_404);
    return;
  }

  if (!it->second.allowBusyCore && !isCoreReady()) {
    response.setStatus(HttpResponse::STATUS_500);
    response.setBody("Core is busy");
    return;
  }

  it->second.handler(this, request, response);
}

bool RpcServer::processJsonRpcRequest(const HttpRequest& request, HttpResponse& response) {

  using namespace JsonRpc;

  JsonRpcRequest jsonRequest;
  JsonRpcResponse jsonResponse;

  RpcServer::addJsonHeaders(response);

  try {
    logger(TRACE) << "JSON-RPC request: " << request.getBody();
    jsonRequest.parseRequest(request.getBody());
    jsonResponse.setId(jsonRequest.getId()); // copy id

    static std::unordered_map<std::string, RpcServer::RpcHandler<JsonMemberMethod>> jsonRpcHandlers = {
      { "getblockcount", { makeMemberMethod(&RpcServer::on_getblockcount), true } },
      { "on_getblockhash", { makeMemberMethod(&RpcServer::on_getblockhash), false } },
      { "getblocktemplate", { makeMemberMethod(&RpcServer::on_getblocktemplate), false } },
      { "getcurrencyid", { makeMemberMethod(&RpcServer::on_get_currency_id), true } },
      { "submitblock", { makeMemberMethod(&RpcServer::on_submitblock), false } },
      { "getlastblockheader", { makeMemberMethod(&RpcServer::on_get_last_block_header), false } },
      { "getblockheaderbyhash", { makeMemberMethod(&RpcServer::on_get_block_header_by_hash), false } },
      { "getblockheaderbyheight", { makeMemberMethod(&RpcServer::on_get_block_header_by_height), false } },
      { "getblockslist", { makeMemberMethod(&RpcServer::on_get_blocks_list), false } },
      { "getblock", { makeMemberMethod(&RpcServer::on_get_block_details), false } },
      { "gettransaction", { makeMemberMethod(&RpcServer::on_get_transaction), false } },
      { "getmempool", { makeMemberMethod(&RpcServer::on_get_mempool), false } },
      { "gettransactionsbypaymentid", { makeMemberMethod(&RpcServer::on_get_transactions_by_payment_id), false } },
    };

    auto it = jsonRpcHandlers.find(jsonRequest.getMethod());
    if (it == jsonRpcHandlers.end()) {
      throw JsonRpcError(JsonRpc::errMethodNotFound);
    }

    if (!it->second.allowBusyCore && !isCoreReady()) {
      throw JsonRpcError(CORE_RPC_ERROR_CODE_CORE_BUSY, "Core is busy");
    }

    it->second.handler(this, jsonRequest, jsonResponse);

  } catch (const JsonRpcError& err) {
    jsonResponse.setError(err);
  } catch (const std::exception& e) {
    jsonResponse.setError(JsonRpcError(JsonRpc::errInternalError, e.what()));
  }

  response.setBody(jsonResponse.getBody());
  logger(TRACE) << "JSON-RPC response: " << jsonResponse.getBody();
  return true;
}

bool RpcServer::restrictRPC(bool is_restricted) {
  m_restricted_rpc = is_restricted;
  return true;
}

void RpcServer::addJsonHeaders(HttpResponse& response) {
  response.addHeader("Content-Type", "application/json");
  response.addHeader("Access-Control-Allow-Origin", "*");
  response.addHeader("Access-Control-Allow-Methods", "GET");
  response.addHeader("Access-Control-Allow-Headers", "application/json");
}

bool RpcServer::isCoreReady() {
  return m_core.currency().isTestnet() || m_p2p.get_payload_object().isSynchronized();
}

//
// Binary handlers
//

bool RpcServer::on_get_blocks(const COMMAND_RPC_GET_BLOCKS_FAST::request& request, COMMAND_RPC_GET_BLOCKS_FAST::response& response) {
  // TODO code duplication see InProcessNode::doGetNewBlocks()
  if (request.block_ids.empty()) {
    response.status = "Failed";
    return false;
  }

  if (request.block_ids.back() != m_core.getBlockIdByHeight(0)) {
    response.status = "Failed";
    return false;
  }

  uint32_t totalBlockCount;
  uint32_t startBlockIndex;
  std::vector<Crypto::Hash> supplement = m_core.findBlockchainSupplement(request.block_ids, COMMAND_RPC_GET_BLOCKS_FAST_MAX_COUNT, totalBlockCount, startBlockIndex);

  response.current_height = totalBlockCount;
  response.start_height = startBlockIndex;

  for (const auto& blockId : supplement) {
    assert(m_core.have_block(blockId));
    auto completeBlock = m_core.getBlock(blockId);
    assert(completeBlock != nullptr);

    response.blocks.resize(response.blocks.size() + 1);
    response.blocks.back().block = asString(toBinaryArray(completeBlock->getBlock()));

    response.blocks.back().txs.reserve(completeBlock->getTransactionCount());
    for (size_t i = 0; i < completeBlock->getTransactionCount(); ++i) {
      response.blocks.back().txs.push_back(asString(toBinaryArray(completeBlock->getTransaction(i))));
    }
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_query_blocks(const COMMAND_RPC_QUERY_BLOCKS::request& request, COMMAND_RPC_QUERY_BLOCKS::response& response) {
  uint32_t startHeight;
  uint32_t currentHeight;
  uint32_t fullOffset;

  if (!m_core.queryBlocks(request.block_ids, request.timestamp, startHeight, currentHeight, fullOffset, response.items)) {
    response.status = "Failed to perform query";
    return false;
  }

  response.start_height = startHeight;
  response.current_height = currentHeight;
  response.full_offset = fullOffset;
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_query_blocks_lite(const COMMAND_RPC_QUERY_BLOCKS_LITE::request& request, COMMAND_RPC_QUERY_BLOCKS_LITE::response& response) {
  uint32_t startHeight;
  uint32_t currentHeight;
  uint32_t fullOffset;
  if (!m_core.queryBlocksLite(request.blockIds, request.timestamp, startHeight, currentHeight, fullOffset, response.items)) {
    response.status = "Failed to perform query";
    return false;
  }

  response.startHeight = startHeight;
  response.currentHeight = currentHeight;
  response.fullOffset = fullOffset;
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_indexes(const COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::request& request, COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES::response& response) {
  std::vector<uint32_t> outputIndexes;
  if (!m_core.get_tx_outputs_gindexs(request.txid, outputIndexes)) {
    response.status = "Failed";
    return true;
  }

  response.o_indexes.assign(outputIndexes.begin(), outputIndexes.end());
  response.status = CORE_RPC_STATUS_OK;
  logger(TRACE) << "COMMAND_RPC_GET_TX_GLOBAL_OUTPUTS_INDEXES: [" << response.o_indexes.size() << "]";
  return true;
}

bool RpcServer::on_get_random_outs(const COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::request& request, COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::response& response) {
  response.status = "Failed";
  if (!m_core.get_random_outs_for_amounts(request, response)) {
    return true;
  }

  response.status = CORE_RPC_STATUS_OK;

  std::stringstream ss;
  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::outs_for_amount outs_for_amount;
  typedef COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS::out_entry out_entry;

  std::for_each(response.outs.begin(), response.outs.end(), [&](outs_for_amount& ofa)  {
    ss << "[" << ofa.amount << "]:";

    assert(ofa.outs.size() && "internal error: ofa.outs.size() is empty");

    std::for_each(ofa.outs.begin(), ofa.outs.end(), [&](out_entry& oe)
    {
      ss << oe.global_amount_index << " ";
    });
    ss << ENDL;
  });
  std::string s = ss.str();
  logger(TRACE) << "COMMAND_RPC_GET_RANDOM_OUTPUTS_FOR_AMOUNTS: " << ENDL << s;
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::onGetPoolChanges(const COMMAND_RPC_GET_POOL_CHANGES::request& request, COMMAND_RPC_GET_POOL_CHANGES::response& response) {
  response.status = CORE_RPC_STATUS_OK;
  std::vector<CryptoNote::Transaction> addedTransactions;
  response.isTailBlockActual = m_core.getPoolChanges(request.tailBlockId, request.knownTxsIds, addedTransactions, response.deletedTxsIds);
  for (auto& tx : addedTransactions) {
    BinaryArray txBlob;
    if (!toBinaryArray(tx, txBlob)) {
      response.status = "Internal error";
      break;
    }

    response.addedTxs.emplace_back(std::move(txBlob));
  }
  return true;
}


bool RpcServer::onGetPoolChangesLite(const COMMAND_RPC_GET_POOL_CHANGES_LITE::request& request, COMMAND_RPC_GET_POOL_CHANGES_LITE::response& response) {
  response.status = CORE_RPC_STATUS_OK;
  response.isTailBlockActual = m_core.getPoolChangesLite(request.tailBlockId, request.knownTxsIds, response.addedTxs, response.deletedTxsIds);

  return true;
}

//
// JSON handlers
//

bool RpcServer::on_get_info(const COMMAND_RPC_GET_INFO::request& request, COMMAND_RPC_GET_INFO::response& response) {
  response.height = m_core.get_current_blockchain_height();
  response.difficulty = m_core.getNextBlockDifficulty();
  response.tx_count = m_core.get_blockchain_total_transactions() - response.height; //without coinbase
  response.tx_pool_size = m_core.get_pool_transactions_count();
  response.alt_blocks_count = m_core.get_alternative_blocks_count();
  uint64_t total_conn = m_p2p.get_connections_count();
  response.outgoing_connections_count = m_p2p.get_outgoing_connections_count();
  response.incoming_connections_count = total_conn - response.outgoing_connections_count;
  response.white_peerlist_size = m_p2p.getPeerlistManager().get_white_peers_count();
  response.grey_peerlist_size = m_p2p.getPeerlistManager().get_gray_peers_count();
  response.last_known_block_index = std::max(static_cast<uint32_t>(1), m_protocolQuery.getObservedHeight()) - 1;
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_height(const COMMAND_RPC_GET_HEIGHT::request& request, COMMAND_RPC_GET_HEIGHT::response& response) {
  response.height = m_core.get_current_blockchain_height();
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions(const COMMAND_RPC_GET_TRANSACTIONS::request& request, COMMAND_RPC_GET_TRANSACTIONS::response& response) {
  std::vector<Hash> vh;
  for (const auto& tx_hex_str : request.txs_hashes) {
    BinaryArray b;
    if (!fromHex(tx_hex_str, b))
    {
      response.status = "Failed to parse hex representation of transaction hash";
      return true;
    }
    if (b.size() != sizeof(Hash))
    {
      response.status = "Failed, size of data mismatch";
    }
    vh.push_back(*reinterpret_cast<const Hash*>(b.data()));
  }
  std::list<Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(vh, txs, missed_txs);

  for (auto& tx : txs) {
    response.txs_as_hex.push_back(toHex(toBinaryArray(tx)));
  }

  for (const auto& miss_tx : missed_txs) {
    response.missed_tx.push_back(Common::podToHex(miss_tx));
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_send_raw_tx(const COMMAND_RPC_SEND_RAW_TX::request& request, COMMAND_RPC_SEND_RAW_TX::response& response) {
  BinaryArray tx_blob;
  if (!fromHex(request.tx_as_hex, tx_blob))
  {
    logger(INFO) << "[on_send_raw_tx]: Failed to parse tx from hexbuff: " << request.tx_as_hex;
    response.status = "Failed";
    return true;
  }

  tx_verification_context tvc = boost::value_initialized<tx_verification_context>();
  if (!m_core.handle_incoming_tx(tx_blob, tvc, false))
  {
    logger(INFO) << "[on_send_raw_tx]: Failed to process tx";
    response.status = "Failed";
    return true;
  }

  if (tvc.m_verifivation_failed)
  {
    logger(INFO) << "[on_send_raw_tx]: tx verification failed";
    response.status = "Failed";
    return true;
  }

  if (!tvc.m_should_be_relayed)
  {
    logger(INFO) << "[on_send_raw_tx]: tx accepted, but not relayed";
    response.status = "Not relayed";
    return true;
  }


  NOTIFY_NEW_TRANSACTIONS::request r;
  r.txs.push_back(asString(tx_blob));
  m_core.get_protocol()->relay_transactions(r);
  //TODO: make sure that tx has reached other nodes here, probably wait to receive reflections from other nodes
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_start_mining(const COMMAND_RPC_START_MINING::request& request, COMMAND_RPC_START_MINING::response& response) {
  if (m_restricted_rpc) {
    response.status = "Failed, restricted handle";
    return false;
  }

  AccountPublicAddress adr;
  if (!m_core.currency().parseAccountAddressString(request.miner_address, adr)) {
    response.status = "Failed, wrong address";
    return true;
  }

  if (!m_core.get_miner().start(adr, static_cast<size_t>(request.threads_count))) {
    response.status = "Failed, mining not started";
    return true;
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_stop_mining(const COMMAND_RPC_STOP_MINING::request& request, COMMAND_RPC_STOP_MINING::response& response) {
  if (m_restricted_rpc) {
    response.status = "Failed, restricted handle";
    return false;
  }

  if (!m_core.get_miner().stop()) {
    response.status = "Failed, mining not stopped";
    return true;
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_stop_daemon(const COMMAND_RPC_STOP_DAEMON::request& request, COMMAND_RPC_STOP_DAEMON::response& response) {
  if (m_restricted_rpc) {
    response.status = "Failed, restricted handle";
    return false;
  }

  if (m_core.currency().isTestnet()) {
    m_p2p.sendStopSignal();
    response.status = CORE_RPC_STATUS_OK;
  } else {
    response.status = CORE_RPC_ERROR_CODE_INTERNAL_ERROR;
    return false;
  }

  return true;
}

//------------------------------------------------------------------------------------------------------------------------------
// JSON RPC methods
//------------------------------------------------------------------------------------------------------------------------------
bool RpcServer::on_getblockcount(const COMMAND_RPC_GETBLOCKCOUNT::request& request, COMMAND_RPC_GETBLOCKCOUNT::response& response) {
    response.count = m_core.get_current_blockchain_height();
    response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_getblockhash(const COMMAND_RPC_GETBLOCKHASH::request& request, COMMAND_RPC_GETBLOCKHASH::response& response) {
  if (request.size() != 1) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong parameters, expected height" };
  }

  uint32_t h = static_cast<uint32_t>(request[0]);
  Crypto::Hash blockId = m_core.getBlockIdByHeight(h);
  if (blockId == NULL_HASH) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
      std::string("To big height: ") + std::to_string(h) + ", current blockchain height = " + std::to_string(m_core.get_current_blockchain_height())
    };
  }

  response = Common::podToHex(blockId);
  return true;
}

namespace {
  uint64_t slow_memmem(void* start_buff, size_t buflen, void* pat, size_t patlen)
  {
    void* buf = start_buff;
    void* end = (char*)buf + buflen - patlen;
    while ((buf = memchr(buf, ((char*)pat)[0], buflen)))
    {
      if (buf>end)
        return 0;
      if (memcmp(buf, pat, patlen) == 0)
        return (char*)buf - (char*)start_buff;
      buf = (char*)buf + 1;
    }
    return 0;
  }
}

bool RpcServer::on_getblocktemplate(const COMMAND_RPC_GETBLOCKTEMPLATE::request& request, COMMAND_RPC_GETBLOCKTEMPLATE::response& response) {
  if (request.reserve_size > TX_EXTRA_NONCE_MAX_COUNT) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_RESERVE_SIZE, "To big reserved size, maximum 255" };
  }

  AccountPublicAddress acc = boost::value_initialized<AccountPublicAddress>();

  if (!request.wallet_address.size() || !m_core.currency().parseAccountAddressString(request.wallet_address, acc)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_WALLET_ADDRESS, "Failed to parse wallet address" };
  }

  Block b = boost::value_initialized<Block>();
  CryptoNote::BinaryArray blob_reserve;
  blob_reserve.resize(request.reserve_size, 0);
  if (!m_core.get_block_template(b, acc, response.difficulty, response.height, blob_reserve)) {
    logger(ERROR) << "Failed to create block template";
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
  }

  BinaryArray block_blob = toBinaryArray(b);
  PublicKey tx_pub_key = CryptoNote::getTransactionPublicKeyFromExtra(b.baseTransaction.extra);
  if (tx_pub_key == NULL_PUBLIC_KEY) {
    logger(ERROR) << "Failed to find tx pub key in coinbase extra";
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to find tx pub key in coinbase extra" };
  }

  if (0 < request.reserve_size) {
    response.reserved_offset = slow_memmem((void*)block_blob.data(), block_blob.size(), &tx_pub_key, sizeof(tx_pub_key));
    if (!response.reserved_offset) {
      logger(ERROR) << "Failed to find tx pub key in blockblob";
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
    }
    response.reserved_offset += sizeof(tx_pub_key) + 3; //3 bytes: tag for TX_EXTRA_TAG_PUBKEY(1 byte), tag for TX_EXTRA_NONCE(1 byte), counter in TX_EXTRA_NONCE(1 byte)
    if (response.reserved_offset + request.reserve_size > block_blob.size()) {
      logger(ERROR) << "Failed to calculate offset for reserved bytes";
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: failed to create block template" };
    }
  } else {
    response.reserved_offset = 0;
  }

  response.blocktemplate_blob = toHex(block_blob);
  response.status = CORE_RPC_STATUS_OK;

  return true;
}

bool RpcServer::on_get_currency_id(const COMMAND_RPC_GET_CURRENCY_ID::request&, COMMAND_RPC_GET_CURRENCY_ID::response& response) {
  Hash currencyId = m_core.currency().genesisBlockHash();
  response.currency_id_blob = Common::podToHex(currencyId);
  return true;
}

bool RpcServer::on_submitblock(const COMMAND_RPC_SUBMITBLOCK::request& request, COMMAND_RPC_SUBMITBLOCK::response& response) {
  if (request.size() != 1) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong param" };
  }

  BinaryArray blockblob;
  if (!fromHex(request[0], blockblob)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_BLOCKBLOB, "Wrong block blob" };
  }

  block_verification_context bvc = boost::value_initialized<block_verification_context>();

  m_core.handle_incoming_block_blob(blockblob, bvc, true, true);

  if (!bvc.m_added_to_main_chain) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_BLOCK_NOT_ACCEPTED, "Block not accepted" };
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}


namespace {
  uint64_t get_block_reward(const Block& blk) {
    uint64_t reward = 0;
    for (const TransactionOutput& out : blk.baseTransaction.outputs) {
      reward += out.amount;
    }
    return reward;
  }
}

void RpcServer::fill_block_header_response(const Block& blk, bool orphan_status, uint64_t height, const Hash& hash, block_header_response& response) {
  response.major_version = blk.majorVersion;
  response.minor_version = blk.minorVersion;
  response.timestamp = blk.timestamp;
  response.prev_hash = Common::podToHex(blk.previousBlockHash);
  response.nonce = blk.nonce;
  response.orphan_status = orphan_status;
  response.height = height;
  response.depth = m_core.get_current_blockchain_height() - height - 1;
  response.hash = Common::podToHex(hash);
  m_core.getBlockDifficulty(static_cast<uint32_t>(height), response.difficulty);
  response.reward = get_block_reward(blk);
}

bool RpcServer::on_get_last_block_header(const COMMAND_RPC_GET_LAST_BLOCK_HEADER::request& request, COMMAND_RPC_GET_LAST_BLOCK_HEADER::response& response) {
  uint32_t last_block_height;
  Hash last_block_hash;

  m_core.get_blockchain_top(last_block_height, last_block_hash);

  Block last_block;
  if (!m_core.getBlockByHash(last_block_hash, last_block)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR, "Internal error: can't get last block hash." };
  }

  fill_block_header_response(last_block, false, last_block_height, last_block_hash, response.block_header);
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_header_by_hash(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::request& request, COMMAND_RPC_GET_BLOCK_HEADER_BY_HASH::response& response) {
  Hash block_hash;

  if (!parse_hash256(request.hash, block_hash)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_WRONG_PARAM,
      "Failed to parse hex representation of block hash. Hex = " + request.hash + '.' };
  }

  Block blk;
  if (!m_core.getBlockByHash(block_hash, blk)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: can't get block by hash. Hash = " + request.hash + '.' };
  }

  if (blk.baseTransaction.inputs.front().type() != typeid(BaseInput)) {
    throw JsonRpc::JsonRpcError{
      CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
      "Internal error: coinbase transaction in the block has the wrong type" };
  }

  uint64_t block_height = boost::get<BaseInput>(blk.baseTransaction.inputs.front()).blockIndex;
  fill_block_header_response(blk, false, block_height, block_hash, response.block_header);
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_header_by_height(const COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::request& request, COMMAND_RPC_GET_BLOCK_HEADER_BY_HEIGHT::response& response) {
  if (m_core.get_current_blockchain_height() <= request.height) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
                                 std::string("To big height: ") + std::to_string(request.height) + ", current blockchain height = " + std::to_string(m_core.get_current_blockchain_height()) };
  }

  Hash block_hash = m_core.getBlockIdByHeight(static_cast<uint32_t>(request.height));
  Block blk;
  if (!m_core.getBlockByHash(block_hash, blk)) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
                                 "Internal error: can't get block by height. Height = " + std::to_string(request.height) + '.' };
  }

  fill_block_header_response(blk, false, request.height, block_hash, response.block_header);
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_blocks_list(const COMMAND_RPC_GET_BLOCKS_LIST::request& request, COMMAND_RPC_GET_BLOCKS_LIST::response& response) {
  if (m_core.get_current_blockchain_height() <= request.height) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_TOO_BIG_HEIGHT,
                                 std::string("To big height: ") + std::to_string(request.height) + ", current blockchain height = " + std::to_string(m_core.get_current_blockchain_height()) };
  }

  uint32_t print_blocks_count = 30;
  uint32_t last_height = request.height - print_blocks_count;
  if (request.height <= print_blocks_count)  {
    last_height = 0;
  }

  for (uint32_t i = request.height; i >= last_height; i--) {
    Hash block_hash = m_core.getBlockIdByHeight(i);
    Block blk;
    if (!m_core.getBlockByHash(block_hash, blk)) {
      throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
                                   "Internal error: can't get block by height. Height = " + std::to_string(i) + '.' };
    }

    size_t tx_cumulative_block_size;
    m_core.getBlockSize(block_hash, tx_cumulative_block_size);
    size_t blokBlobSize = getObjectBinarySize(blk);
    size_t minerTxBlobSize = getObjectBinarySize(blk.baseTransaction);
    difficulty_type blockDiff;
    m_core.getBlockDifficulty(static_cast<uint32_t>(i), blockDiff);

    block_short_response block_short;
    block_short.timestamp = blk.timestamp;
    block_short.height = i;
    block_short.hash = Common::podToHex(block_hash);
    block_short.cumul_size = blokBlobSize + tx_cumulative_block_size - minerTxBlobSize;
    block_short.tx_count = blk.transactionHashes.size() + 1;
    block_short.difficulty = blockDiff;

    response.blocks.push_back(block_short);

    if (i == 0)
      break;
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_block_details(const COMMAND_RPC_GET_BLOCK_DETAILS::request& request, COMMAND_RPC_GET_BLOCK_DETAILS::response& response) {
  Hash hash;

  try {
    uint32_t height = boost::lexical_cast<uint32_t>(request.hash);
    hash = m_core.getBlockIdByHeight(height);
  } catch (boost::bad_lexical_cast &) {
    if (!parse_hash256(request.hash, hash)) {
      throw JsonRpc::JsonRpcError{
          CORE_RPC_ERROR_CODE_WRONG_PARAM,
          "Failed to parse hex representation of block hash. Hex = " + request.hash + '.' };
    }
  }

  Block blk;
  if (!m_core.getBlockByHash(hash, blk)) {
    throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get block by hash. Hash = " + request.hash + '.' };
  }

  if (blk.baseTransaction.inputs.front().type() != typeid(BaseInput)) {
    throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: coinbase transaction in the block has the wrong type" };
  }

  block_header_response block_header;
  response.block.height = boost::get<BaseInput>(blk.baseTransaction.inputs.front()).blockIndex;

  Crypto::Hash tmp_hash = m_core.getBlockIdByHeight(response.block.height);
  bool is_orphaned = hash != tmp_hash;
  fill_block_header_response(blk, is_orphaned, response.block.height, hash, block_header);

  response.block.major_version = block_header.major_version;
  response.block.minor_version = block_header.minor_version;
  response.block.timestamp = block_header.timestamp;
  response.block.prev_hash = block_header.prev_hash;
  response.block.nonce = block_header.nonce;
  response.block.hash = block_header.hash;
  response.block.depth = block_header.depth;
  response.block.orphan_status = block_header.orphan_status;
  m_core.getBlockDifficulty(response.block.height, response.block.difficulty);
  m_core.getBlockCumulativeDifficulty(response.block.height, response.block.cumulativeDifficulty);

  response.block.reward = block_header.reward;

  std::vector<size_t> blocksSizes;
  if (!m_core.getBackwardBlocksSizes(response.block.height, blocksSizes, parameters::CRYPTONOTE_REWARD_BLOCKS_WINDOW)) {
    return false;
  }
  response.block.sizeMedian = Common::medianValue(blocksSizes);

  size_t blockSize = 0;
  if (!m_core.getBlockSize(hash, blockSize)) {
    return false;
  }
  response.block.transactionsCumulativeSize = blockSize;

  size_t blokBlobSize = getObjectBinarySize(blk);
  size_t minerTxBlobSize = getObjectBinarySize(blk.baseTransaction);
  response.block.blockSize = blokBlobSize + response.block.transactionsCumulativeSize - minerTxBlobSize;

  uint64_t alreadyGeneratedCoins;
  if (!m_core.getAlreadyGeneratedCoins(hash, alreadyGeneratedCoins)) {
    return false;
  }
  response.block.alreadyGeneratedCoins = std::to_string(alreadyGeneratedCoins);

  if (!m_core.getGeneratedTransactionsNumber(response.block.height, response.block.alreadyGeneratedTransactions)) {
    return false;
  }

  uint64_t prevBlockGeneratedCoins = 0;
  if (response.block.height > 0) {
    if (!m_core.getAlreadyGeneratedCoins(blk.previousBlockHash, prevBlockGeneratedCoins)) {
      return false;
    }
  }
  uint64_t maxReward = 0;
  uint64_t currentReward = 0;
  int64_t emissionChange = 0;
  size_t blockGrantedFullRewardZone =  CryptoNote::parameters::CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE;
  response.block.effectiveSizeMedian = std::max(response.block.sizeMedian, blockGrantedFullRewardZone);

  if (!m_core.getBlockReward(response.block.sizeMedian, 0, prevBlockGeneratedCoins, 0, maxReward, emissionChange)) {
    return false;
  }
  if (!m_core.getBlockReward(response.block.sizeMedian, response.block.transactionsCumulativeSize, prevBlockGeneratedCoins, 0, currentReward, emissionChange)) {
    return false;
  }

  response.block.baseReward = maxReward;
  if (maxReward == 0 && currentReward == 0) {
    response.block.penalty = static_cast<double>(0);
  } else {
    if (maxReward < currentReward) {
      return false;
    }
    response.block.penalty = static_cast<double>(maxReward - currentReward) / static_cast<double>(maxReward);
  }

  // Base transaction adding
  transaction_short_response base_transaction_short;
  base_transaction_short.hash = Common::podToHex(getObjectHash(blk.baseTransaction));
  base_transaction_short.fee = 0;
  base_transaction_short.amount_out = get_outs_money_amount(blk.baseTransaction);
  base_transaction_short.size = getObjectBinarySize(blk.baseTransaction);
  response.block.transactions.push_back(base_transaction_short);

  std::list<Crypto::Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(blk.transactionHashes, txs, missed_txs);

  response.block.totalFeeAmount = 0;

  for (const Transaction& tx : txs) {
    transaction_short_response transaction_short;
    uint64_t amount_in = 0;
    get_inputs_money_amount(tx, amount_in);
    uint64_t amount_out = get_outs_money_amount(tx);

    transaction_short.hash = Common::podToHex(getObjectHash(tx));
    transaction_short.fee = amount_in - amount_out;
    transaction_short.amount_out = amount_out;
    transaction_short.size = getObjectBinarySize(tx);
    response.block.transactions.push_back(transaction_short);

    response.block.totalFeeAmount += transaction_short.fee;
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transaction(const COMMAND_RPC_GET_TRANSACTION_DETAILS::request& request, COMMAND_RPC_GET_TRANSACTION_DETAILS::response& response) {
  Hash hash;

  if (!parse_hash256(request.hash, hash)) {
    throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "Failed to parse hex representation of transaction hash. Hex = " + request.hash + '.' };
  }

  std::vector<Crypto::Hash> tx_ids;
  tx_ids.push_back(hash);

  std::list<Crypto::Hash> missed_txs;
  std::list<Transaction> txs;
  m_core.getTransactions(tx_ids, txs, missed_txs, true);

  if (1 == txs.size()) {
    response.tx = txs.front();
  } else {
    throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "transaction wasn't found. Hash = " + request.hash + '.' };
  }

  Crypto::Hash blockHash;
  uint32_t blockHeight;
  if (m_core.getBlockContainingTx(hash, blockHash, blockHeight)) {
    Block blk;
    if (m_core.getBlockByHash(blockHash, blk)) {
      size_t tx_cumulative_block_size;
      m_core.getBlockSize(blockHash, tx_cumulative_block_size);
      size_t blokBlobSize = getObjectBinarySize(blk);
      size_t minerTxBlobSize = getObjectBinarySize(blk.baseTransaction);
      block_short_response block_short;

      block_short.timestamp = blk.timestamp;
      block_short.height = blockHeight;
      block_short.hash = Common::podToHex(blockHash);
      block_short.cumul_size = blokBlobSize + tx_cumulative_block_size - minerTxBlobSize;
      block_short.tx_count = blk.transactionHashes.size() + 1;
      response.block = block_short;
      response.txDetails.confirmations = m_protocolQuery.getObservedHeight() - blockHeight;
    }
  }

  uint64_t amount_in = 0;
  get_inputs_money_amount(response.tx, amount_in);
  uint64_t amount_out = get_outs_money_amount(response.tx);

  response.txDetails.hash = Common::podToHex(getObjectHash(response.tx));
  response.txDetails.fee = amount_in - amount_out;
  if (amount_in == 0)
    response.txDetails.fee = 0;
  response.txDetails.amount_out = amount_out;
  response.txDetails.size = getObjectBinarySize(response.tx);

  uint64_t mixin;
  if (!m_core.getMixin(response.tx, mixin)) {
    return false;
  }
  response.txDetails.mixin = mixin;

  Crypto::Hash paymentId;
  if (CryptoNote::getPaymentIdFromTxExtra(response.tx.extra, paymentId)) {
    response.txDetails.paymentId = Common::podToHex(paymentId);
  } else {
    response.txDetails.paymentId = "";
  }

  response.txDetails.extra.raw = response.tx.extra;

  std::vector<CryptoNote::TransactionExtraField> txExtraFields;
  parseTransactionExtra(response.tx.extra, txExtraFields);
  for (const CryptoNote::TransactionExtraField& field : txExtraFields) {
    if (typeid(CryptoNote::TransactionExtraPadding) == field.type()) {
      response.txDetails.extra.padding.push_back(std::move(boost::get<CryptoNote::TransactionExtraPadding>(field).size));
    }
    else if (typeid(CryptoNote::TransactionExtraPublicKey) == field.type()) {
      //response.txDetails.extra.publicKey = std::move(boost::get<CryptoNote::TransactionExtraPublicKey>(field).publicKey);
      response.txDetails.extra.publicKey = CryptoNote::getTransactionPublicKeyFromExtra(response.tx.extra);
    }
    else if (typeid(CryptoNote::TransactionExtraNonce) == field.type()) {
      response.txDetails.extra.nonce.push_back(Common::toHex(boost::get<CryptoNote::TransactionExtraNonce>(field).nonce.data(), boost::get<CryptoNote::TransactionExtraNonce>(field).nonce.size()));
    }
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_mempool(const COMMAND_RPC_GET_MEMPOOL::request& request, COMMAND_RPC_GET_MEMPOOL::response& response) {
  auto pool = m_core.getMemoryPool();
  for (const CryptoNote::tx_memory_pool::TransactionDetails txd : pool) {
    mempool_transaction_response mempool_transaction;
    uint64_t amount_out = getOutputAmount(txd.tx);

    mempool_transaction.hash = Common::podToHex(txd.id);
    mempool_transaction.fee = txd.fee;
    mempool_transaction.amount_out = amount_out;
    mempool_transaction.size = txd.blobSize;
    mempool_transaction.receiveTime = txd.receiveTime;
    mempool_transaction.keptByBlock = txd.keptByBlock;
    mempool_transaction.max_used_block_height = txd.maxUsedBlock.height;
    mempool_transaction.max_used_block_id = Common::podToHex(txd.maxUsedBlock.id);
    mempool_transaction.last_failed_height = txd.lastFailedBlock.height;
    mempool_transaction.last_failed_id = Common::podToHex(txd.lastFailedBlock.id);
    response.mempool.push_back(mempool_transaction);
  }
  response.status = CORE_RPC_STATUS_OK;
  return true;
}

bool RpcServer::on_get_transactions_by_payment_id(const COMMAND_RPC_GET_TRANSACTIONS_BY_PAYMENT_ID::request& request, COMMAND_RPC_GET_TRANSACTIONS_BY_PAYMENT_ID::response& response) {
  if (!request.payment_id.size()) {
    throw JsonRpc::JsonRpcError{ CORE_RPC_ERROR_CODE_WRONG_PARAM, "Wrong parameters, expected payment_id" };
  }
  logger(Logging::DEBUGGING, Logging::WHITE) << "RPC request came: Search by Payment ID: " << request.payment_id;

  Crypto::Hash paymentId;
  std::vector<Transaction> transactions;

  if (!parse_hash256(request.payment_id, paymentId)) {
    throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_WRONG_PARAM,
        "Failed to parse Payment ID: " + request.payment_id + '.' };
  }

  if (!m_core.getTransactionsByPaymentId(paymentId, transactions)) {
    throw JsonRpc::JsonRpcError{
        CORE_RPC_ERROR_CODE_INTERNAL_ERROR,
        "Internal error: can't get transactions by Payment ID: " + request.payment_id + '.' };
  }

  for (const Transaction& tx : transactions) {
    transaction_short_response transaction_short;
    uint64_t amount_in = 0;
    get_inputs_money_amount(tx, amount_in);
    uint64_t amount_out = get_outs_money_amount(tx);

    transaction_short.hash = Common::podToHex(getObjectHash(tx));
    transaction_short.fee = amount_in - amount_out;
    transaction_short.amount_out = amount_out;
    transaction_short.size = getObjectBinarySize(tx);
    response.transactions.push_back(transaction_short);
  }

  response.status = CORE_RPC_STATUS_OK;
  return true;
}


}
