// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_H
#define BITCOIN_POW_H
#include <arith_uint256.h>
#include <consensus/params.h>
#include <uint256.h>
#include <cstdint>

class CBlockHeader;
class CBlockIndex;

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit);

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params);
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits,
const CBlockIndex* pindexPrev);

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params);

std::optional<arith_uint256> DeriveTarget( unsigned int nBits, const uint256 pow_limit);
bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params);

#endif // BITCOIN_POW_H
