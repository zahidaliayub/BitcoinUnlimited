Federated-Soft-Hard Extension Blocks
====================================

Purpose:  Permissionless innovation in blockchain technology

Strategy:  Create an extension block that can be deployed live as a "federated" (multisignature trusted commitments, permissionless) extension block, seamlessly transition to a soft fork extension block (Bitcoin trust model, but requires miner "permission") based on miner voting, and finally to a hard fork if desired.

Rationale:  This allows extension block technology to be deployed on live, value-carrying networks without requiring permission.  This allows the extension block to gain runtime with value at stake yet not by creating a competitive alt-coin or sidechain.  When the network (miners) accept the technology, it can be automatically (without any code changes) enabled as a
soft or hard fork in the Bitcoin network.

Terminology
-------------

"FSH administrator": entity that has control over the FSH extension block.  This either be federated signers or miners depending on the lifecycle of the FSH extension block.

Theory of Operation
------------------------------------


### Genesis and Federated Mode

Two well-known addresses are created: the FSH ingress address and the FSH holding address.  These addresses' private keys are held by the federated signers (the FSH extension block administrators).  These addresses and FSH block information is announced on the Bitcoin blockchain via a 

To move funds into the extension block, a user sends money to the ingress address.  When this transaction is confirmed, funds are considered "staged" for ingress.  A user can create this transaction without contacting the FSH administrator.

Periodically, the administrator creates an FSH update transaction that commits a new extension block and can move money into and out of the extension block.  To move money into the extension block, "staged" transactions are spent as inputs (the administrator can choose none, some or all currently staged transactions).

To move money out of the extension block, UTXOs are created paying the appropriate (as defined by data inside the extension block) Bitcoin address.

If the value of the inputs is larger than the outputs (money is entering the extension block), an additional output is created that pays to the FSH holding address.  If the value of the outputs is larger than the inputs, a prior UTXO from the FSH holding address is used.


### Transitioning to a Soft Fork

A voting protocol is used so that miners can indicate that they will support a particular FSH extension block, and choose a soft-fork date and an activation date.  Many possible techniques exist, for example BIP9 bit-versions, or BIP100-like coinbase message voting.

After the "soft fork" date, miners will not accept any transactions or blocks containing transactions that spend ingress address or holding address funds unless those transactions properly adhere to the FSH block (these) semantics.

Administrators now publically disclose the FSH ingress and holding address private keys.  After disclosure, all transactions containing these keys effectively become "anyone-can-spend" transactions.  However, just like traditional "anyone-can-spend" transactions, the miner soft fork prevents any spending that is inconsistent with the FSH block semantics.  Similarly to Segregated Witness (SegWit) and other "anyone-can-spend" soft forks, a majority of miners would need to choose to break the new rules to spend these funds.


### Security Model

The security model pre-soft-fork is based on trust in the FSH administrators.  They are custodians of the BTC on the Bitcoin blockchain that backs the funds in the FSH extension block.

The security model post-soft-fork is exactly as in SegWit.   In one sense, it weakens Bitcoin's security model -- today a majority of miners can prevent you from spending your funds on the majority chain but cannot sign a transaction stealing your funds.  However, once funds are in anyone-can-spend transactions, anyone can sign valid transactions spending your funds.  This can happen on the majority chain if the majority of miners choose to allow it, or can happen on a minority chain.  However, it should be noted that if the majority of miners choose to steal funds they can simply do so by allowing transactions without a valid signature (Bitcoin's security model is fundamentally based on the premise the the majority of miners are honest).  So the only difference in these two cases is that in the latter situation there is an undeniable record in the blockchain showing that the funds were taken without a valid signature.  






Bitcoin Blockchain Transactions
------------------------------------

### Genesis/Initialization Transaction

This transaction creates and begins a FSH extension block system.

TXIs:
can be anything

TXOs:

0: first extension block
1: continuity txo
2. genesis txo, contains:
   document commitment
   deposit address
   backing address


### Ingress Transaction

A user sends BTC to the FSH extension block via an Ingress transaction

This transaction simply sends funds to an address controlled by the FSH administrators (federated signers or miners)

A user can also particip

### Update Transaction

An administrator or miner extends the FSH blockchain, and moves money into and out of it using an update transaction.

Inputs: UXTOs of any Ingress Transactions

Outputs:
  Any money leaving the fsb blockchain
  fsb blockchain update commitment

The block specified by the fsb update commitment must be consistent with the Bitcoin inputs and outputs also specified in this transaction.
Since a transaction is atomic, this ensures that the FSH blockchain is always consistent with the Bitcoin blockchain.

### Closing Transaction

This transaction ends this extension blockchain.





