#!/usr/bin/env python3
# Copyright (c) 2021-2024 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.mininode import *
from test_framework.test_framework import SparksTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.messages import hash256
from test_framework.p2p import P2PInterface
from test_framework.test_framework import SparksTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, hex_str_to_bytes

'''
rpc_mnauth.py

Tests mnauth RPC command
'''


class FakeMNAUTHTest(SparksTestFramework):
    def set_test_params(self):
        self.set_sparks_test_params(2, 1, fast_dip3_enforcement=True)

    def run_test(self):

        masternode = self.mninfo[0]
        masternode.node.add_p2p_connection(P2PInterface())

        protx_hash = masternode.proTxHash
        #TODO: Fix that with basic BLS
        public_key = masternode.pubKeyOperator

        # The peerinfo should not yet contain verified_proregtx_hash/verified_pubkey_hash
        assert "verified_proregtx_hash" not in masternode.node.getpeerinfo()[-1]
        assert "verified_pubkey_hash" not in masternode.node.getpeerinfo()[-1]
        # Fake-Authenticate the P2P connection to the masternode
        node_id = masternode.node.getpeerinfo()[-1]["id"]
        assert masternode.node.mnauth(node_id, protx_hash, public_key)
        # The peerinfo should now contain verified_proregtx_hash and verified_pubkey_hash
        peerinfo = masternode.node.getpeerinfo()[-1]
        assert "verified_proregtx_hash" in peerinfo
        assert "verified_pubkey_hash" in peerinfo
        assert_equal(peerinfo["verified_proregtx_hash"], protx_hash)
        assert_equal(peerinfo["verified_pubkey_hash"], hash256(hex_str_to_bytes(public_key))[::-1].hex())
        # Test some error cases
        null_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        assert_raises_rpc_error(-8, "proTxHash invalid", masternode.node.mnauth,
                                                         node_id,
                                                         null_hash,
                                                         public_key)
        assert_raises_rpc_error(-8, "publicKey invalid", masternode.node.mnauth,
                                                         node_id,
                                                         protx_hash,
                                                         null_hash)
        assert not masternode.node.mnauth(-1, protx_hash, public_key)


if __name__ == '__main__':
    FakeMNAUTHTest().main()
