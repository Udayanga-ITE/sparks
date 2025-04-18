#!/usr/bin/env python3
# Copyright (c) 2020-2023 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
from test_framework.test_framework import SparksTestFramework
from test_framework.util import assert_equal

'''
rpc_masternode.py

Test "masternode" rpc subcommands
'''

class RPCMasternodeTest(SparksTestFramework):
    def set_test_params(self):
        self.set_sparks_test_params(4, 3, fast_dip3_enforcement=True)

    def run_test(self):
        self.log.info("test that results from `winners` and `payments` RPCs match")
        blockhash = ""
        payments = []
        # we expect some masternodes to have 0 operator reward and some to have non-0 operator reward
        checked_0_operator_reward = False
        checked_non_0_operator_reward = False
        while not checked_0_operator_reward or not checked_non_0_operator_reward:
            self.nodes[0].generate(1)
            bi = self.nodes[0].getblockchaininfo()
            height = bi["blocks"]
            blockhash = bi["bestblockhash"]
            winners_payee = self.nodes[0].masternode("winners")[str(height)]
            payments = self.nodes[0].masternode("payments", blockhash)
            assert_equal(len(payments), 1)
            payments_block = payments[0]
            payments_block_payees = payments_block["masternodes"][0]["payees"]
            payments_payee = ""
            for i in range(0, len(payments_block_payees)):
                payments_payee += payments_block_payees[i]["address"]
                if i < len(payments_block_payees) - 1:
                    payments_payee += ", "
            assert_equal(payments_block["height"], height)
            assert_equal(payments_block["blockhash"], blockhash)
            assert_equal(winners_payee, payments_payee)
            if len(payments_block_payees) == 1:
                checked_0_operator_reward = True
            if len(payments_block_payees) > 1:
                checked_non_0_operator_reward = True

        self.log.info("test various `payments` RPC options")
        payments1 = self.nodes[0].masternode("payments", blockhash, -1)
        assert_equal(payments, payments1)
        payments2_1 = self.nodes[0].masternode("payments", blockhash, 2)
        # using chaintip as a start block should return 1 block only
        assert_equal(len(payments2_1), 1)
        assert_equal(payments[0], payments2_1[0])
        payments2_2 = self.nodes[0].masternode("payments", blockhash, -2)
        # using chaintip as a start block should return 2 blocks now, with the tip being the last one
        assert_equal(len(payments2_2), 2)
        assert_equal(payments[0], payments2_2[-1])

        self.log.info("test that `masternode payments` results at chaintip match `getblocktemplate` results for that block")
        gbt_masternode = self.nodes[0].getblocktemplate()["masternode"]
        self.nodes[0].generate(1)
        payments_masternode = self.nodes[0].masternode("payments")[0]["masternodes"][0]
        for i in range(0, len(gbt_masternode)):
            assert_equal(gbt_masternode[i]["payee"], payments_masternode["payees"][i]["address"])
            assert_equal(gbt_masternode[i]["script"], payments_masternode["payees"][i]["script"])
            assert_equal(gbt_masternode[i]["amount"], payments_masternode["payees"][i]["amount"])

        self.log.info("test that `masternode payments` results and `protx info` results match")
        # we expect some masternodes to have 0 operator reward and some to have non-0 operator reward
        checked_0_operator_reward = False
        checked_non_0_operator_reward = False
        while not checked_0_operator_reward or not checked_non_0_operator_reward:
            payments_masternode = self.nodes[0].masternode("payments")[0]["masternodes"][0]
            protx_info = self.nodes[0].protx("info", payments_masternode["proTxHash"])
            if len(payments_masternode["payees"]) == 1:
                assert_equal(protx_info["state"]["payoutAddress"], payments_masternode["payees"][0]["address"])
                checked_0_operator_reward = True
            else:
                assert_equal(len(payments_masternode["payees"]), 2)
                option1 = protx_info["state"]["payoutAddress"] == payments_masternode["payees"][0]["address"] and \
                    protx_info["state"]["operatorPayoutAddress"] == payments_masternode["payees"][1]["address"]
                option2 = protx_info["state"]["payoutAddress"] == payments_masternode["payees"][1]["address"] and \
                    protx_info["state"]["operatorPayoutAddress"] == payments_masternode["payees"][0]["address"]
                assert option1 or option2
                checked_non_0_operator_reward = True
            self.nodes[0].generate(1)

        self.log.info("test that `masternode outputs` show correct list")
        addr1 = self.nodes[0].getnewaddress()
        addr2 = self.nodes[0].getnewaddress()
        self.nodes[0].sendmany('', {addr1: 1000, addr2: 1000})
        self.nodes[0].generate(1)
        # we have 3 masternodes that are running already and 2 new outputs we just created
        assert_equal(len(self.nodes[0].masternode("outputs")), 5)

if __name__ == '__main__':
    RPCMasternodeTest().main()
