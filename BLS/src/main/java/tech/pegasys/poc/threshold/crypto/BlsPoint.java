
package tech.pegasys.poc.threshold.crypto;


import tech.pegasys.poc.threshold.crypto.altbn128.AltBn128Fq2PointWrapper;
import tech.pegasys.poc.threshold.crypto.altbn128.AltBn128PointWrapper;
import tech.pegasys.poc.threshold.crypto.bls12381.Bls12381PointWrapper;
import tech.pegasys.poc.threshold.crypto.bls12381.Bls12381Fq2PointWrapper;

import java.math.BigInteger;

/**
 * BLS public key - either a share or the group public key.
 */
public interface BlsPoint {
    // Add a point to this point.
    BlsPoint add(BlsPoint other);

    // Multiple this point by a scalar.
    BlsPoint scalarMul(BigInteger scalar);


    // Return true if this point is the point at infinity.
    boolean isAtInfinity();


    // Negation is needed so the point can be verified on blockchain.
    BlsPoint negate();

    // Store the point data.
    byte[] store();

    // Load the point base on data.
    static BlsPoint load(byte[] data) {
        if (data.length == AltBn128PointWrapper.STORED_LEN) {
            return AltBn128PointWrapper.load(data);
        }
        if (data.length == AltBn128Fq2PointWrapper.STORED_LEN) {
            return AltBn128Fq2PointWrapper.load(data);
        }
        if (data.length == Bls12381PointWrapper.STORED_LEN) {
            return Bls12381PointWrapper.load(data);
        }
        if (data.length == Bls12381Fq2PointWrapper.STORED_LEN) {
            return Bls12381Fq2PointWrapper.load(data);
        }


        throw new Error("Not implemented yet");
    }
}
