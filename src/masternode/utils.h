// Copyright (c) 2014-2024 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <evo/deterministicmns.h>
#include <primitives/transaction.h>
#include <consensus/validation.h>
#include <sync.h>
#include <uint256.h>
#include <set>
#include <atomic>
#include <cstdint>


#ifndef BITCOIN_MASTERNODE_UTILS_H
#define BITCOIN_MASTERNODE_UTILS_H

class CConnman;
class CDeterministicMNManager;
class CMasternodeSync;
class CBlockIndex;
struct CJContext;

class CMasternodeUtils
{
public:
    static void DoMaintenance(CConnman &connman, CDeterministicMNManager& dmnman,
                              const CMasternodeSync& mn_sync, const CJContext& cj_ctx);
};

class CMasternodeAutoRevokeProcessor
{
private:
    static std::set<uint256> recentlyProcessed; // Track recently processed to avoid duplicates
    static Mutex cs_recentlyProcessed;
    
public:
    static bool ProcessAutoRevokes(ChainstateManager& chainman, std::unique_ptr<PeerManager>& peerman, CSporkManager& sporkman, CDeterministicMNManager& dmnman, const CBlockIndex* pindex);
    static CMutableTransaction CreateAutoRevokeTx(ChainstateManager& chainman, const uint256& proTxHash, const CBlockIndex* pindex);
    static bool IsRecentlyProcessed(const uint256& proTxHash);
    static void AddToRecentlyProcessed(const uint256& proTxHash);
    static void CleanupRecentlyProcessed(int nHeight);
    
    // Statistics
    static int64_t GetTotalAutoRevokes();
    static void IncrementAutoRevokeCount();
};

#endif // BITCOIN_MASTERNODE_UTILS_H
