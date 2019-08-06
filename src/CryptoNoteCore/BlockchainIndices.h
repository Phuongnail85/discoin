// Copyright (c) 2011-2016 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>
#include <unordered_map>
#include <map>

#include <boost/container_hash/hash.hpp>

#include "crypto/hash.h"
#include "CryptoNoteBasic.h"

namespace CryptoNote {

class ISerializer;

inline size_t paymentIdHash(const Crypto::Hash& paymentId) {
  return boost::hash_range(std::begin(paymentId.data), std::end(paymentId.data));
}

class PaymentIdIndex {
public:
  explicit PaymentIdIndex(bool enabled);

  bool add(const Transaction& transaction);
  bool remove(const Transaction& transaction);
  bool find(const Crypto::Hash& paymentId, std::vector<Crypto::Hash>& transactionHashes);
  void clear();

  void serialize(ISerializer& s);

  template<class Archive>
  void serialize(Archive& archive, unsigned int version) {
    archive & index;
  }
private:
  std::unordered_multimap<Crypto::Hash, Crypto::Hash, std::function<decltype(paymentIdHash)>> index;
  bool enabled = false;
};

class TimestampBlocksIndex {
public:
  explicit TimestampBlocksIndex(bool enabled);

  bool add(uint64_t timestamp, const Crypto::Hash& hash);
  bool remove(uint64_t timestamp, const Crypto::Hash& hash);
  bool find(uint64_t timestampBegin, uint64_t timestampEnd, uint32_t hashesNumberLimit, std::vector<Crypto::Hash>& hashes, uint32_t& hashesNumberWithinTimestamps);
  void clear();

  void serialize(ISerializer& s);

  template<class Archive>
  void serialize(Archive& archive, unsigned int version) {
    archive & index;
  }
private:
  std::multimap<uint64_t, Crypto::Hash> index;
  bool enabled = false;
};

class TimestampTransactionsIndex {
public:
  explicit TimestampTransactionsIndex(bool enabled);

  bool add(uint64_t timestamp, const Crypto::Hash& hash);
  bool remove(uint64_t timestamp, const Crypto::Hash& hash);
  bool find(uint64_t timestampBegin, uint64_t timestampEnd, uint64_t hashesNumberLimit, std::vector<Crypto::Hash>& hashes, uint64_t& hashesNumberWithinTimestamps);
  void clear();

  void serialize(ISerializer& s);

  template<class Archive>
  void serialize(Archive& archive, unsigned int version) {
    archive & index;
  }
private:
  std::multimap<uint64_t, Crypto::Hash> index;
  bool enabled = false;
};

class GeneratedTransactionsIndex {
public:
  explicit GeneratedTransactionsIndex(bool enabled);

  bool add(const Block& block);
  bool remove(const Block& block);
  bool find(uint32_t height, uint64_t& generatedTransactions);
  void clear();

  void serialize(ISerializer& s);

  template<class Archive>
  void serialize(Archive& archive, unsigned int version) {
    archive & index;
    archive & lastGeneratedTxNumber;
  }
private:
  std::unordered_map<uint32_t, uint64_t> index;
  uint64_t lastGeneratedTxNumber;
  bool enabled = false;
};

class OrphanBlocksIndex {
public:
  explicit OrphanBlocksIndex(bool enabled);

  bool add(const Block& block);
  bool remove(const Block& block);
  bool find(uint32_t height, std::vector<Crypto::Hash>& blockHashes);
  void clear();
private:
  std::unordered_multimap<uint32_t, Crypto::Hash> index;
  bool enabled = false;
};

}
