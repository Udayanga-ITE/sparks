Sparks Core version v18.2.2
=========================

Release is now available from:

  <https://www.sparkspay.io/downloads/#wallets>

This is a new hotfix version release.

This release is optional for all nodes; however, v18.2.2 or higher is required
to be able to use testnet right until v19 hard fork activation. Earlier
versions will not be able to sync past block 847000 on testnet.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/sparkspay/sparks/issues>


Upgrading and downgrading
=========================

How to Upgrade
--------------

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes for older versions), then run the
installer (on Windows) or just copy over /Applications/Sparks-Qt (on Mac) or
sparksd/sparks-qt (on Linux). If you upgrade after DIP0003 activation and you were
using version < 0.13 you will have to reindex (start with -reindex-chainstate
or -reindex) to make sure your wallet has all the new data synced. Upgrading
from version 0.13 should not require any additional actions.

When upgrading from a version prior to 18.0.1, the
first startup of Sparks Core will run a migration process which can take anywhere
from a few minutes to thirty minutes to finish. After the migration, a
downgrade to an older version is only possible with a reindex
(or reindex-chainstate).

Downgrade warning
-----------------

### Downgrade to a version < v18.2.2

Downgrading to a version older than v18.2.2 is supported.

### Downgrade to a version < v18.0.1

Downgrading to a version older than v18.0.1 is not supported due to changes in
the indexes database folder. If you need to use an older version, you must
either reindex or re-sync the whole chain.

Notable changes
===============

Testnet Breaking Changes
------------------------

A new testnet only LLMQ has been added. This LLMQ is of the type LLMQ_25_67; this LLMQ is only active on testnet.
This LLMQ will not remove the llmq_20_70 from testnet; however that quorum (likely) will not form and will perform no role.
See the [diff](https://github.com/sparkspay/sparks/pull/5225/files#diff-e70a38a3e8c2a63ca0494627301a5c7042141ad301193f78338d97cb1b300ff9R451-R469) for specific parameters of the LLMQ.

This LLMQ will become active at the height of 847000. **This will be a breaking change and a hard fork for testnet**
This LLMQ is not activated with the v19 hardfork; as such testnet will experience two hardforks. One at height 847000,
and the other to be determined by the BIP9 hard fork process.

Remote Procedure Call (RPC) Changes
-----------------------------------

### The new RPCs are:
None

### The removed RPCs are:
None

### Changes in existing RPCs introduced through bitcoin backports:
None

### Sparks-specific changes in existing RPCs:
None

Please check `help <command>` for more detailed information on specific RPCs.

Command-line options
--------------------
None

Please check `Help -> Command-line options` in Qt wallet or `sparksd --help` for
more information.

Backports from Bitcoin Core
---------------------------
None

Other changes
-------------
#5247 is backported to improve debugging experience.

v18.2.2 Change log
==================

See detailed [set of changes](https://github.com/sparkspay/sparks/compare/v18.2.1...sparkspay:v18.2.2).

Credits
=======

Thanks to everyone who directly contributed to this release:

- Odysseas Gabrielides
- UdjinM6

As well as everyone that submitted issues, reviewed pull requests, helped debug the release candidates, and write DIPs that were implemented in this release.

Older releases
==============

Sparks was previously known as Darkcoin.

Darkcoin tree 0.8.x was a fork of Litecoin tree 0.8, original name was XCoin
which was first released on Jan/18/2014.

Darkcoin tree 0.9.x was the open source implementation of masternodes based on
the 0.8.x tree and was first released on Mar/13/2014.

Darkcoin tree 0.10.x used to be the closed source implementation of Darksend
which was released open source on Sep/25/2014.

Sparks Core tree 0.11.x was a fork of Bitcoin Core tree 0.9,
Darkcoin was rebranded to Sparks.

Sparks Core tree 0.12.0.x was a fork of Bitcoin Core tree 0.10.

Sparks Core tree 0.12.1.x was a fork of Bitcoin Core tree 0.12.

These release are considered obsolete. Old release notes can be found here:

- [v18.2.1](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-18.2.2.md) released Jan/17/2023
- [v18.2.0](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-18.2.0.md) released Jan/01/2023
- [v18.1.1](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-18.1.1.md) released January/08/2023
- [v18.1.0](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-18.1.0.md) released October/09/2022
- [v18.0.2](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-18.0.2.md) released October/09/2022
- [v18.0.1](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-18.0.1.md) released August/17/2022
- [v0.17.0.3](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.17.0.3.md) released June/07/2021
- [v0.17.0.2](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.17.0.2.md) released May/19/2021
- [v0.16.1.1](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.16.1.1.md) released November/17/2020
- [v0.16.1.0](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.16.1.0.md) released November/14/2020
- [v0.16.0.1](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.16.0.1.md) released September/30/2020
- [v0.15.0.0](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.15.0.0.md) released Febrary/18/2020
- [v0.14.0.5](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.14.0.5.md) released December/08/2019
- [v0.14.0.4](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.14.0.4.md) released November/22/2019
- [v0.14.0.3](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.14.0.3.md) released August/15/2019
- [v0.14.0.2](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.14.0.2.md) released July/4/2019
- [v0.14.0.1](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.14.0.1.md) released May/31/2019
- [v0.14.0](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.14.0.md) released May/22/2019
- [v0.13.3](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.13.3.md) released Apr/04/2019
- [v0.13.2](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.13.2.md) released Mar/15/2019
- [v0.13.1](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.13.1.md) released Feb/9/2019
- [v0.13.0](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.13.0.md) released Jan/14/2019
- [v0.12.3.4](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.12.3.4.md) released Dec/14/2018
- [v0.12.3.3](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.12.3.3.md) released Sep/19/2018
- [v0.12.3.2](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.12.3.2.md) released Jul/09/2018
- [v0.12.3.1](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.12.3.1.md) released Jul/03/2018
- [v0.12.2.3](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.12.2.3.md) released Jan/12/2018
- [v0.12.2.2](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.12.2.2.md) released Dec/17/2017
- [v0.12.2](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.12.2.md) released Nov/08/2017
- [v0.12.1](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.12.1.md) released Feb/06/2017
- [v0.12.0](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.12.0.md) released Aug/15/2015
- [v0.11.2](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.11.2.md) released Mar/04/2015
- [v0.11.1](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.11.1.md) released Feb/10/2015
- [v0.11.0](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.11.0.md) released Jan/15/2015
- [v0.10.x](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.10.0.md) released Sep/25/2014
- [v0.9.x](https://github.com/sparkspay/sparks/blob/master/doc/release-notes/sparks/release-notes-0.9.0.md) released Mar/13/2014
