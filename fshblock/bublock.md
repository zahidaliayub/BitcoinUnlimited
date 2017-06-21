Bitcoin Unlimited FSH Extension Block
=====================================




Theory of Operation
------------------------------------


# Blockchain

A BU FSH block is committed periodically to the Bitcoin blockchain via a FSH Update transaction.  For these "committed" blocks, the difficulty of the FSH block is the max of the difficulty of the bitcoin block and the FSH block (effectively a FSH block committed in an FSH Update does not need to be separately mined).

But the BU FSH extension blocks can also be mined at approximately 1 minute intervals.

Since the difficulty of the committed FSH block is likely to greatly exceed the cumulative difficulty of many mined FSH blocks, a miner could ignore all mined FSH blocks, including all of the FSH transactions since the last committed FSH block into his block.  This game-theoretic issue is analagous to the well known unlimited size block mining conundrum:  why should a miner extend the bitcoin blockchain, allowing the prior block to gain fees rather than create a larger block with all the transactions contained within the prior block and all new transactions? (there's actually 2 reasons: cumulative difficulty, and cooperation benefits all)  A corollary to this question is whether an extremely high transaction fee would cause the same behavior even with a limited size block and block subsidy.

To solve this issue the way transaction fees work is changed.

First, there exists a transaction fee pool.  A portion of all transaction fees mined by a block go into this pool, as described below.  The quantity in the pool for block N+1 can be calculated by looking at all prior blocks.  Every mined block receives a fraction of all fees in the pool (1/2048th rounded down -- or specifically poolQuantity >> 11)

Second, mined blocks can designate a portion of the total transaction fees in their block to be given to the next committed block.

Finally, transactions have an activate timestamp.  A block's timestamp must be >= the transaction activate timestamp, or the transaction cannot be included in the block.  That is, for every transaction in a block: (timeDelta = blockTimestamp - txTimestamp) >= 0

The block's coinbase is given a greater than or equal to 0 portion of the fee that decreases as the interval between the block timestamp and the transaction timestamp widens.  That is:
blockfee += Bfee(txFee, timeDelta).
The fee pool receives any left over portion: poolfee += txFee - Bfee(txFee, timeDelta).
The pool always gets some fee.  That is: BFee(txFee, for all X >= 0) < txFee.

The exact Bfee function is TBD but it must satisfy the above constraints.  Good candidates are a [sigmoid decay](http://www.wolframalpha.com/input/?i=plot+f(x)+%3D+.75*(1-+1%2F(1%2Be%5E(5-x)))+between+0+and+10) or [exponential decay](https://en.wikipedia.org/wiki/Exponential_decay) or an approximation of decay by linearly decreasing until 0, then 0.

And consider starting at 75% of the total fee, i.e. BFee(txFee,0) -> txFee*.75

## Proposed function

```
Bfee(txFee, timeDelta) ->
MAX=.75
MIN=.05
timeDelta = timeDelta/60  # scale appropriately
timeDelta = timeDelta-3   # shift the fall of the s curve

return txFee*MIN + txFee*(MAX-MIN)*(1-1/(1+e^(-timeDelta)))
```

Specified mathematically:
[plot f(x) = .05 + .75*(1- 1/(1+e^(3-x))) between 0 and 10](http://www.wolframalpha.com/input/?i=plot+f(x)+%3D+.05+%2B+.75*(1-+1%2F(1%2Be%5E(3-x)))+between+0+and+10)


For efficiency and to avoid floating point rounding issues, this graph should be translated into an integral look up table, with fee values of 0 to 100% ranging from 0 to 256 and then:

```
Bfee(txFee, timeDelta) ->
// scale timeDelta specified in seconds to the scale of the table entry index
timeDelta /= tableScaling;
// If we go off the end of the table, use the last entry
if (timeDelta >= tableMax) timeDelta = tableMax-1;

// multiplying by the table value effectively multiples by 256 times the
// desired function, so divide the 256 back out by shifting 8 bits
return (txFee * table[timeDelta])>>8;
```


# Effects

1. First, this means that a miner that creates transactions with artificially high fees will always pay some portion of that fee into the pool, losing money (this is an issue in Bitcoin that severely limits the confidence in the information contained in fees, which disallows use of aggregate fee data for functions like block size control).  This is a desirable feature since it increases confidence that the fees represent actual economic activity.

(idea: For the purposes of retiring uncommitted transactions, if the Bfee == 0, the transaction is now invalid.  But what if txFee == 0?  Or tx is invalid if blockTimestamp - txTimestamp > MAX_AGE, or add a retirement timestamp into the transaction)


2. Fees provided to the committed blocks via mined blocks can be greater than the fees available if those transactions are directly mined by the committed blocks.


Miners may not be honest about block creation time, either inadvertently or deliberately to optimize fee payment.  This is not a problem.  Selecting an early block timestamp disallows subsequent transactions from being included in that block and selecting a future block timestamp reduces the fraction of fees paid to you verses fees paid to the pool.

And similarly to Bitcoin, honest miners should disallow extreme values; blocks whose timestamp is > 1 minute in the future or 1 minute less than the prior block's timestamp should be considered invalid by miners who receive them.
(Option: a miner may not create a block timestamp that is <= the prior block's timestamp) 

[Bitcoin currently has a game-theoretic failure mode where miners collectively choose to ignore the rule that block timestamps must not diverge from real time and they advance "block time" faster than real time.  This would cause a downward difficulty adjustment, allowing the miners to increase their coinbase reward.  However like many such "attacks" it requires a majority of dishonest miners]




