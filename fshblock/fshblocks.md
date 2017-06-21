Federated-Soft-Hard Extension Blocks
====================================

Purpose:  Permissionless innovation in blockchain technology

Strategy:  Create an extension block that can be deployed live as a "federated" (multisignature trusted commitments, permissionless) extension block, seamlessly transition to a soft fork extension block (Bitcoin trust model, but requires miner "permission") based on miner voting, and finally to a hard fork if desired.

Rationale:  This allows extension block technology to be deployed on live, value-carrying networks without requiring permission.  This allows the extension block to gain runtime with value at stake yet not by creating a competitive alt-coin or sidechain.  When the network (miners) accept the technology, it can be automatically (without any code changes) enabled as a
soft or hard fork in the Bitcoin network.

Terminology
-------------

**continuity txi/txo**
  The "continuity transaction input or output" is a mechanism in the bitcoin blockchain that ensures that extension block N+1 immediately succeeds extension block N

**document commitment**
  The SHA256 of an XML document that describes UI and human consumable information about this extension block.

**FSH administrator**
  Entity that has control over the FSH extension block.  This either be federated signers or miners depending on the lifecycle of the FSH extension block.

**FSH ingress address**
  A special bitcoin address that users spend funds to to indicate that these funds should be moved to the extension block.

**FSH holding address**
  A special bitcoin address with funds that back all the bitcoin in the extension block.
  

Theory of Operation
------------------------------------


### Genesis and Federated Mode

Two well-known addresses are created: the FSH ingress address and the FSH holding address.  These addresses' private keys are held by the federated signers (the FSH extension block administrators).  These addresses and FSH block information are announced on the Bitcoin blockchain via a special transaction called the FSH extension block genesis transaction.

To move funds into the extension block, a user sends money to the ingress address.  When this transaction is confirmed, funds are considered "staged" for ingress.  A user can create this transaction without contacting the FSH administrator.

Periodically, the administrator creates an FSH update transaction that commits a new extension block and can move money into and out of the extension block.  This update transaction spends a specific output, called the "continuity output" that was created in the prior update transaction.  This ensures that a single chain of extension block transactions will be committed to the bitcoin blockchain, even if multiple extension blocks are created at height N.  By following continuity transactions to find extension blocks, a extension blockchain is formed, so it is unnecessary for the extension block to contain the hash of the prior extension block.  However, doing so may allow for more efficient operation, and would be necessary to transition to a hard fork operation mode that abandons the current bitcoin block format.

To move money into the extension block, "staged" transactions are spent as inputs (the administrator can choose none, some or all currently staged transactions).

To move money out of the extension block, UTXOs are created paying the appropriate (as defined by data inside the extension block) Bitcoin address.

If the value of the inputs is larger than the outputs (money is entering the extension block), an additional output is created that pays to the FSH holding address.  If the value of the outputs is larger than the inputs, a prior UTXO from the FSH holding address is added to the inputs, and any change is paid to the FSH holding address.

Since a new extension block is committed and money is moved into and out of the FSH holding address in a single transaction, it happens atomically.  Therefore, the administrators can ensure that the value represented in the extension block never goes out of sync with the payment flows into and out of the holding address.


An federated extension block may be preferred by companies implementing certain functionality, so some extension blocks may persist in this operation mode indefinitely.  This is a weaker security model than bitcoin's proof-of-work.  At the same time, a federated extension block is public, cannot be deleted or modified, and could require end-user signatures to sign extension block transactions.  So many aspects of bitcoin's security model that are not available in (say) a corporate SQL database remain to protect the users of federated extension blocks.


### Transitioning to a Soft Fork

A voting protocol is used so that miners can indicate that they will support a particular FSH extension block, and choose a soft-fork date and an activation date.  Many possible techniques exist, for example BIP9 bit-versions, or BIP100-like coinbase message voting.

After the "soft fork" date, miners will not accept any transactions or blocks containing transactions that spend ingress address or holding address funds unless those transactions properly adhere to the FSH block (these) semantics.

Administrators now publically disclose the FSH ingress and holding address private keys.  After disclosure, all transactions containing these keys effectively become "anyone-can-spend" transactions.  However, just like traditional "anyone-can-spend" transactions, the miner soft fork prevents any spending that is inconsistent with the FSH block semantics.  Similarly to Segregated Witness (SegWit) and other "anyone-can-spend" soft forks, a majority of miners would need to choose to break the new rules to spend these funds.

The operation of the soft fork extension block remains exactly the same as the federated extension block.  This allows the federated mode to be used as a trial before transitioning to a soft fork.


### Transitioning to a Soft-Hard Fork

A soft-hard fork is a "soft fork" from bitcoin's perspective (a narrowing of the ruleset so existing clients see all blocks as valid), yet it effectively constitutes a hard fork since the soft fork deliberately makes bitcoin unusable.  This could be used as a prelude to a hard fork, or to reduce complexity by effectively deprecating almost all features in the bitcoin blockchain.  In this scenario, a majority of miners start enforcing a rule where the only three transaction types are allowed on the bitcoin blockchain:
1. Transactions that spend to the FSH block ingress address (if the extension block is sophisticated enough to accept bitcoin UTXOs, you could also disallow the first transaction type)
2. FSH block update transactions
3. (and the bitcoin coinbase)

This forces all economic activity to the extension block, and after some time the bitcoin block would effectively be reduced to header + coinbase + FSH block.


### Transitioning to a Hard Fork

The term hard fork encompasses an infinite number of possibilities.  This possibility that is most interesting within the context of FSH extension blocks is to stop mining the bitcoin blockchain and start mining and extending the extension block.  Whether this is possible or desirable depends upon the contents of the extension block.  Some extension blocks may not ever be intended to move to a hard fork, and so may lack necessary features.  Key features are all the features that form bitcoin's current blocks, and the additional ability to spend bitcoin outputs.  This is different behavior than operation in the Federated and Soft Fork modes where the extension block does not allow bitcoin UTXOs to be spent in the extension block.

The decision to hard fork is beyond the scope of this document and can happen through all of the processes employed or conceptualized for any hard fork, but the end result should be agreement to hard fork at a particular bitcoin block height.

At the point of the hard fork, participating miners stop mining the Bitcoin blockchain and start mining the extension blockchain.  Subsequent blocks and FSH update transactions in the bitcoin blockchain are simply ignored.  In a contentious hard fork, it would be possible to have a viable bitcoin blockchain with functioning FSH extension block AND a functioning FSH block hard fork.  Yet from a social perspective a hard fork is unlikely without overwhelming consensus.  Since the extension block is performing the same function before and after the hard fork, there is little reason to hard fork if a significant group would like to continue the bitcoin blockchain.




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

```
0. first extension block hash
  OP_RETURN, OP_PUSHDATAn(block hash)
1. continuity txo
2. genesis txo, contains:
  0. deposit address
  1. backing address
  2. document commitment
        OP_RETURN, OP_PUSHDATAn(deposit address), OP_PUSHDATAn(backing address), OP_PUSHDATAn(document commitment)
3. (optional, many) additional TXOs (change) 
```


### Ingress Transaction

To move value into the extension block, a user must give value to the FSH administrators and provide instructions as to how this value should be imported into the extension block.

An ingress transaction is this mechanism.  First, this transaction transfers value by sending funds to an address controlled by the FSH administrators (federated signers or miners).

To provide instructions, several techniques are possible:

1. The user creates a extension block "mint" transaction that is signed with the same private key(s) as the ingress transaction.  To be valid, the update transaction must both spend the ingress transaction and reference an extension block containing this mint transaction.
2. The FSH administrator creates an extension block transaction that pays to the same outputs as were used as inputs in the ingress transaction.
3. The user adds additional information to the Ingress Transaction such as a destination address or equivalent in the extension block.  The FSH administrator creates a "mint" transaction that pays to this address.


### Update Transaction

An administrator or miner extends the FSH blockchain, and moves money into and out of it using an update transaction.

Inputs: UXTOs of any Ingress Transactions

Outputs:
  * Any money leaving the fsb blockchain
  * fsb blockchain update commitment
  * (optional) software update commitment (TBD)

The block specified by the fsb update commitment must be consistent with the Bitcoin inputs and outputs also specified in this transaction.
Since a transaction is atomic, this ensures that the FSH blockchain is always consistent with the Bitcoin blockchain.

### Closing Transaction

This transaction ends this extension blockchain.


### Extension Block Description Document

XML Tags:

All short text fields (name, brief) should be written without formatting or markup.  Longer fields (info, contract) can be writting in TBD format. Exactly one instance of each tag is expected at a particular location in the hierarchy, unless the document indicates otherwise with the "optional" or "many" annotation.

* tag "doc"
  * parameter "name": Extension block name.  Do not use in UI!  use language-specific name.
  * tag "software": location of software and code names that would appear in Update Transaction outputs
    * tag "sw" (many): an instance of compatible software
      * parameter "name": name of the software
      * parameter "code": code name (would appear in Update Transaction outputs) to certify new versions
      * parameter "extends": if this software is a plugin, this is the name of the host software
      * parameter "url": location of the software
  * tag "admins" (optional):  Block of identity information about the extension block administrators
    * TBD      
  * tag [[ISO 639-1 or 639-2 language code](https://www.loc.gov/standards/iso639-2/langhome.html)] (many, up to 1 per language):
    * tag "name": extension block name for display
    * tag "brief": Brief summary of the purpose of the extension block
    * tag "info" (optional): Longer description
    * tag "contract" (optional): Legal contract (if applicable)

#### Extension Block Description Template and Example

```XML
<?xml version="1.0" encoding="UTF-8"?>
<doc name="myBlock">
  <software>
    <sw name="my ext block sw" code="buE" extends="Bitcoin Unlimited" url="http://www.bitcoinunlimited.info/myBlock" />
    <sw .../>
  </software>

  <eng>
    <name>myBlock</name>
    <brief>Example extension block</brief>
  </eng>
  <fre>
    <name>monBlock</name>
    <brief>Pardon, Je ne parle pas bien francais</brief>
  </fre>
</doc>
```
