package tech.pegasys.poc.threshold.crypto;

import tech.pegasys.poc.threshold.crypto.altbn128.AltBn128CryptoProvider;
import tech.pegasys.poc.threshold.crypto.bls12381.Bls12381CryptoProvider;
import tech.pegasys.poc.threshold.crypto.bn254.Bn254CryptoProvider;
import tech.pegasys.poc.threshold.crypto.bn254cx.Bn254CXCryptoProvider;


import java.math.BigInteger;

public interface BlsCryptoProvider {
    enum CryptoProviderTypes {
        LOCAL_ALT_BN_128,
        LOCAL_BLS12_381,
        BN254,
        BN254CX
    }
    enum DigestAlgorithm {
        KECCAK256
    }

    static BlsCryptoProvider getInstance(CryptoProviderTypes type, DigestAlgorithm digestAlgorithm) {
        switch (type) {
            case LOCAL_ALT_BN_128:
                return new AltBn128CryptoProvider(digestAlgorithm);
            case LOCAL_BLS12_381:
                return new Bls12381CryptoProvider(digestAlgorithm);
            case BN254:
                return new Bn254CryptoProvider(digestAlgorithm);
            case BN254CX:
                return new Bn254CXCryptoProvider(digestAlgorithm);
            default:
                throw new Error("Unknown BlsCryptoProvider type: " + type);
        }
    }


    BigInteger modPrime(BigInteger val);

    BigInteger getPrimeModulus();

    BlsPoint createPointE1(BigInteger scalar);
    BlsPoint hashToCurveE1(byte[] data);
    BlsPoint getBasePointE1();

    BlsPoint createPointE2(BigInteger scalar);
    BlsPoint hashToCurveE2(byte[] data);
    BlsPoint getBasePointE2();

    /**
     * Create a signature as a point on the E1 curve.
     *
     * @param privateKey Private key to sign data with.
     * @param data Data to be signed.
     * @return signature.
     */
    BlsPoint sign(BigInteger privateKey, byte[] data);

    /**
     * Verify a signature.
     *
     * @param publicKey Point on the E2 curve to verify the data with.
     * @param data Data to be verified.
     * @param signature Signature on E1 curve.
     * @return true if the signature is verified.
     */
    boolean verify(BlsPoint publicKey, byte[] data, BlsPoint signature);

    boolean verify2(BlsPoint publicKey, byte[] data, BlsPoint signature);

}
