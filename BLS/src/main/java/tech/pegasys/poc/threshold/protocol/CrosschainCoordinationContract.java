package tech.pegasys.poc.threshold.protocol;


import tech.pegasys.poc.threshold.crypto.BlsPoint;

// Crosschain Coordination Contract which sits on the Coordination Blockchain.
// In this PoC the contract stores the group public key.
public class CrosschainCoordinationContract {
    BlsPoint publicKey = null;

    public void setPublicKey(BlsPoint key) {
        this.publicKey = key;
    }

    public BlsPoint getPublicKey() {
        return this.publicKey;
    }

}
