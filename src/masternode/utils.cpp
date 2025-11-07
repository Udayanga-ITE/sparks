// Copyright (c) 2014-2024 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <masternode/utils.h>
#include <evo/deterministicmns.h>

#ifdef ENABLE_WALLET
#include <coinjoin/client.h>
#endif
#include <masternode/sync.h>
#include <txmempool.h>
#include <consensus/validation.h>
#include <net.h>
#include <net_processing.h>
#include <shutdown.h>
#include <validation.h>
#include <util/ranges.h>
#include <coinjoin/context.h>
#include <validationinterface.h>

#include <set>
#include <atomic>
extern std::unique_ptr<CConnman> g_connman;

// Static member initialization
std::set<uint256> CMasternodeAutoRevokeProcessor::recentlyProcessed;
Mutex CMasternodeAutoRevokeProcessor::cs_recentlyProcessed;
static std::atomic<int64_t> nTotalAutoRevokes{0};

bool CMasternodeAutoRevokeProcessor::ProcessAutoRevokes(ChainstateManager& chainman, std::unique_ptr<PeerManager>& peerman, CSporkManager& sporkman, CDeterministicMNManager& dmnman, const CBlockIndex* pindex)
{
    if (!pindex) {
        return false;
    }
    
    // Check if we've reached activation height
    if (!DeploymentActiveAt(*pindex, Params().GetConsensus(), Consensus::DEPLOYMENT_MN_AR)) {
        return false;
    }
    
    // Only check every 100 blocks to reduce overhead
    // if (pindex->nHeight % 100 != 0) {
        // std::cout << "Only check every 100 blocks Faild" << std::endl;
        // return false;
    // }
    
    // Cleanup old entries from recently processed
    CleanupRecentlyProcessed(pindex->nHeight);
    
    CDeterministicMNList mnList = dmnman.GetListForBlock(pindex);
    std::vector<uint256> eligibleMNs = dmnman.GetMnEligibleForAutoRevoke(mnList, pindex, MnType::Regular);
    
    if (eligibleMNs.empty()) {
        return true;
    }
    
    LogPrintf("CMasternodeAutoRevokeProcessor::%s -- Found %d masternodes eligible for auto-revoke at height %d\n",
              __func__, eligibleMNs.size(), pindex->nHeight);
    
    int successCount = 0;
    int skipCount = 0;
    
    // Limit processing to prevent spam (max 10 per check)
    const size_t MAX_AUTO_REVOKES_PER_CHECK = 10;
    size_t processLimit = std::min(eligibleMNs.size(), MAX_AUTO_REVOKES_PER_CHECK);
    
    // Process each eligible masternode
    for (size_t i = 0; i < processLimit; i++) {
        const auto& proTxHash = eligibleMNs[i];
        
        // Skip if recently processed
        if (IsRecentlyProcessed(proTxHash)) {
            skipCount++;
            continue;
        }
        
        try {
            CMutableTransaction tx = CreateAutoRevokeTx(chainman, proTxHash, pindex);
            
            // Submit transaction to mempool
            CTransactionRef txRef = MakeTransactionRef(tx);
            CTxMemPool& mempool = *chainman.ActiveChainstate().GetMempool();
            // Check if already in mempool or chain
            if (mempool.exists(txRef->GetHash())) {
                LogPrintf("CMasternodeAutoRevokeProcessor::%s -- Auto-revoke tx already in mempool: %s\n",
                        __func__, txRef->GetHash().ToString());
                AddToRecentlyProcessed(proTxHash);
                skipCount++;
                continue;
            }
            
            // Get current time for mempool entry
            int64_t nAcceptTime = GetTime();
            // MempoolAcceptResult result = AcceptToMemoryPool(chainman.ActiveChainstate(), txRef, nAcceptTime, sporkman, /*bypass_limits=*/false, /*test_accept=*/false);
            // if (result.m_result_type != MempoolAcceptResult::ResultType::VALID) {
            //     LogPrintf("CMasternodeAutoRevokeProcessor::%s -- Failed to submit auto-revoke tx: %s\n",
            //             __func__, txRef->GetHash().ToString());
            //     continue;
            // }
            
            // Mark as recently processed
            AddToRecentlyProcessed(proTxHash);
            IncrementAutoRevokeCount();
            successCount++;
            
            // Notify the network
            GetMainSignals().TransactionAddedToMempool(txRef, nAcceptTime, mempool.GetAndIncrementSequence());

            peerman->RelayTransaction(txRef->GetHash());

            LogPrintf("CMasternodeAutoRevokeProcessor::%s -- Successfully created and submitted auto-revoke tx %s for masternode %s\n",
                     __func__, txRef->GetHash().ToString(), proTxHash.ToString());
                     
        } catch (const std::exception& e) {
            LogPrintf("CMasternodeAutoRevokeProcessor::%s -- Exception while processing auto-revoke for %s: %s\n",
                     __func__, proTxHash.ToString(), e.what());
        }
    }
    
    if (successCount > 0 || skipCount > 0) {
        LogPrintf("CMasternodeAutoRevokeProcessor::%s -- Processed: %d successful, %d skipped out of %d eligible\n",
                 __func__, successCount, skipCount, eligibleMNs.size());
    }
    
    return true;
}

CMutableTransaction CMasternodeAutoRevokeProcessor::CreateAutoRevokeTx(ChainstateManager& chainman, const uint256& proTxHash, const CBlockIndex* pindex)
{
    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.nType = TRANSACTION_PROVIDER_UPDATE_REVOKE;
    
    const bool isV19active{DeploymentActiveAfter(WITH_LOCK(cs_main, return chainman.ActiveChain().Tip();), Params().GetConsensus(), Consensus::DEPLOYMENT_V19)};
    CProUpRevTx revokeTx;
    revokeTx.nVersion = CProUpRevTx::GetVersion(isV19active);
    revokeTx.proTxHash = proTxHash;
    revokeTx.nReason = CProUpRevTx::REASON_AUTO_REVOKE;
    
    // Create inputs hash for replay protection
    // Use block hash + proTxHash as unique identifier
    CHashWriter hw(SER_GETHASH, 0);
    hw << pindex->GetBlockHash();
    hw << proTxHash;
    revokeTx.inputsHash = hw.GetHash();
    
    // Leave signature empty for auto-revoke
    revokeTx.sig = CBLSSignature();
    
    // Create payload
    SetTxPayload(tx, revokeTx);
    
    // Add dummy input (no real input needed for auto-revoke)
    CTxIn txin(COutPoint(uint256(), (uint32_t)-1));
    tx.vin.push_back(txin);
    
    // Add minimal output (dust)
    CTxOut txout;
    txout.nValue = 0;
    txout.scriptPubKey = CScript() << OP_RETURN;
    tx.vout.push_back(txout);
    
    return tx;
}

bool CMasternodeAutoRevokeProcessor::IsRecentlyProcessed(const uint256& proTxHash)
{
    LOCK(cs_recentlyProcessed);
    return recentlyProcessed.count(proTxHash) > 0;
}

void CMasternodeAutoRevokeProcessor::AddToRecentlyProcessed(const uint256& proTxHash)
{
    LOCK(cs_recentlyProcessed);
    recentlyProcessed.insert(proTxHash);
}

void CMasternodeAutoRevokeProcessor::CleanupRecentlyProcessed(int nHeight)
{
    // Clean up every 1000 blocks
    if (nHeight % 1000 != 0) {
        return;
    }
    
    LOCK(cs_recentlyProcessed);
    // Clear all - they should have been revoked by now
    recentlyProcessed.clear();
    LogPrintf("CMasternodeAutoRevokeProcessor::%s -- Cleaned up recently processed list at height %d\n",
             __func__, nHeight);
}

int64_t CMasternodeAutoRevokeProcessor::GetTotalAutoRevokes()
{
    return nTotalAutoRevokes.load();
}

void CMasternodeAutoRevokeProcessor::IncrementAutoRevokeCount()
{
    nTotalAutoRevokes++;
}

void CMasternodeUtils::DoMaintenance(CConnman& connman, CDeterministicMNManager& dmnman,
                                     const CMasternodeSync& mn_sync, const CJContext& cj_ctx)
{
    if (!mn_sync.IsBlockchainSynced()) return;
    if (ShutdownRequested()) return;

    std::vector<CDeterministicMNCPtr> vecDmns; // will be empty when no wallet
#ifdef ENABLE_WALLET
    cj_ctx.walletman->ForEachCJClientMan([&vecDmns](const std::unique_ptr<CCoinJoinClientManager>& clientman) {
        clientman->GetMixingMasternodesInfo(vecDmns);
    });
#endif // ENABLE_WALLET

    // Don't disconnect masternode connections when we have less then the desired amount of outbound nodes
    int nonMasternodeCount = 0;
    connman.ForEachNode(CConnman::AllNodes, [&](const CNode* pnode) {
        if ((!pnode->IsInboundConn() &&
            !pnode->IsFeelerConn() &&
            !pnode->IsManualConn() &&
            !pnode->m_masternode_connection &&
            !pnode->m_masternode_probe_connection)
            ||
            // treat unverified MNs as non-MNs here
            pnode->GetVerifiedProRegTxHash().IsNull()) {
            nonMasternodeCount++;
        }
    });
    if (nonMasternodeCount < int(connman.GetMaxOutboundNodeCount())) {
        return;
    }

    connman.ForEachNode(CConnman::AllNodes, [&](CNode* pnode) {
        if (pnode->m_masternode_probe_connection) {
            // we're not disconnecting masternode probes for at least PROBE_WAIT_INTERVAL seconds
            if (GetTime<std::chrono::seconds>() - pnode->m_connected < PROBE_WAIT_INTERVAL) return;
        } else {
            // we're only disconnecting m_masternode_connection connections
            if (!pnode->m_masternode_connection) return;
            if (!pnode->GetVerifiedProRegTxHash().IsNull()) {
                const auto tip_mn_list = dmnman.GetListAtChainTip();
                // keep _verified_ LLMQ connections
                if (connman.IsMasternodeQuorumNode(pnode, tip_mn_list)) {
                    return;
                }
                // keep _verified_ LLMQ relay connections
                if (connman.IsMasternodeQuorumRelayMember(pnode->GetVerifiedProRegTxHash())) {
                    return;
                }
                // keep _verified_ inbound connections
                if (pnode->IsInboundConn()) {
                    return;
                }
            } else if (GetTime<std::chrono::seconds>() - pnode->m_connected < PROBE_WAIT_INTERVAL) {
                // non-verified, give it some time to verify itself
                return;
            } else if (pnode->qwatch) {
                // keep watching nodes
                return;
            }
        }

#ifdef ENABLE_WALLET
        bool fFound = ranges::any_of(vecDmns, [&pnode](const auto& dmn){ return pnode->addr == dmn->pdmnState->addr; });
        if (fFound) return; // do NOT disconnect mixing masternodes
#endif // ENABLE_WALLET
        if (fLogIPs) {
            LogPrint(BCLog::NET_NETCONN, "Closing Masternode connection: peer=%d, addr=%s\n", pnode->GetId(),
                     pnode->addr.ToStringAddrPort());
        } else {
            LogPrint(BCLog::NET_NETCONN, "Closing Masternode connection: peer=%d\n", pnode->GetId());
        }
        pnode->fDisconnect = true;
    });
}
