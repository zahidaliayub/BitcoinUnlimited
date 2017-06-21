from simplefshchain import *
from simplefshwallet import *

def Test():
    # any valid address for the purpose of this test
    fshDepositAddr = "mrDDZJ637G3M5hiKz9ehdgBRM6y1fo5gMw"
    fshBackingAddr = "mnPf6UGVgLEahHDXyrsZE5kMnVAK8RzVjB"

    GENESIS_PARENT = b"0"*32
    NO_MINT = SimpleTransaction([],[])

    wallet = SimpleRamWallet()
    chain =  SimpleBlockChain(fshDepositAddr,fshBackingAddr,GENESIS_PARENT)


    k = wallet.getNewAddress()
    spendMint = SimpleTxOut(k, 1000)
    t = SimpleTransaction([],[spendMint])

    b0 = SimpleBlock([t],GENESIS_PARENT)
    b0.solve()
    chain.submitBlock(b0)

    tip = chain.tip()
    newaddr = wallet.getNewAddress()
    t2 = wallet.spend(newaddr, 10, tip.utxo)

    pdb.set_trace()
    b1 = SimpleBlock([t2],b0)
    b1.solve()
    chain.submitBlock(b1)

    pdb.set_trace()
