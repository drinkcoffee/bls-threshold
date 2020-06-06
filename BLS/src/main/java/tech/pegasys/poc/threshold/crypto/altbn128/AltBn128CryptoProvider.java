package tech.pegasys.poc.threshold.crypto.altbn128;

import tech.pegasys.pantheon.crypto.Hash;
import tech.pegasys.pantheon.crypto.altbn128.*;
import tech.pegasys.pantheon.util.bytes.Bytes32;
import tech.pegasys.pantheon.util.bytes.BytesValue;
import tech.pegasys.pantheon.util.bytes.BytesValues;
import tech.pegasys.pantheon.util.bytes.MutableBytesValue;
import tech.pegasys.poc.threshold.crypto.BlsCryptoProvider;
import tech.pegasys.poc.threshold.crypto.BlsPoint;
import tech.pegasys.poc.threshold.crypto.CryptoProviderBase;

import java.math.BigInteger;
import java.security.MessageDigest;

public class AltBn128CryptoProvider extends CryptoProviderBase implements BlsCryptoProvider {

    public AltBn128CryptoProvider(BlsCryptoProvider.DigestAlgorithm alg) {
        super(alg);
    }

    public BigInteger modPrime(BigInteger val) {
        return val.mod(AltBn128Fq12Pairer.CURVE_ORDER);
    }

    public BigInteger getPrimeModulus() {
        return AltBn128Fq12Pairer.CURVE_ORDER;
    }


    public BlsPoint createPointE1(BigInteger scalar) {
        AltBn128Point basedPoint = AltBn128Point.g1();
        return new AltBn128PointWrapper(basedPoint.multiply(scalar));
    }

    public BlsPoint getBasePointE1() {
        AltBn128Point basedPoint = AltBn128Point.g1();
        return new AltBn128PointWrapper(basedPoint);
    }






    public BlsPoint createPointE2(BigInteger scalar) {
        AltBn128Fq2Point basedPoint = AltBn128Fq2Point.g2();
        return new AltBn128Fq2PointWrapper(basedPoint.multiply(scalar));
    }

    public BlsPoint getBasePointE2() {
        AltBn128Fq2Point basedPoint = AltBn128Fq2Point.g2();
        return new AltBn128Fq2PointWrapper(basedPoint);
    }




    /**
     * Verify a signature.
     *
     * @param publicKey Point on the E2 curve to verify the data with.
     * @param data Data to be verified.
     * @param signature Signature on E1 curve.
     * @return true if the signature is verified.
     */
    public boolean verify(BlsPoint publicKey, byte[] data, BlsPoint signature) {
        BlsPoint hashOfData = hashToCurveE1(data);
        BlsPoint basePointE2 = getBasePointE2();

        long start = System.nanoTime();
        Fq12 pair1 = AltBn128Fq12Pairer.pair(((AltBn128PointWrapper)hashOfData).point, ((AltBn128Fq2PointWrapper)publicKey).point);
        long mid = System.nanoTime();
        //System.out.println("Pair 1: " + pair1);
        Fq12 pair2 = AltBn128Fq12Pairer.pair(((AltBn128PointWrapper)signature).point, ((AltBn128Fq2PointWrapper)basePointE2).point);
        //System.out.println("Pair 2: " + pair2);
        long end = System.nanoTime();



        Fq12 exponent = Fq12.one();
        exponent = exponent.multiply(pair1);
        long end2 = System.nanoTime();
        Fq12 result1 = AltBn128Fq12Pairer.finalize(exponent);
        long end3 = System.nanoTime();
        // System.out.println("Result1: " + result1);

        exponent = Fq12.one();
        exponent = exponent.multiply(pair2);
        long end4 = System.nanoTime();
        Fq12 result2 = AltBn128Fq12Pairer.finalize(exponent);
        long end5 = System.nanoTime();
        // System.out.println("Result2: " + result2);

//        System.err.println("mid - start: " + (mid-start));
//        System.err.println("end- mid: " + (end - mid));
//        System.err.println("end2 - end: " + (end2 - end));
//        System.err.println("end3 - end2: " + (end3 - end2));
//        System.err.println("end4 - end3: " + (end4 - end3));
//        System.err.println("end5 - end4: " + (end5 - end4));

        return result1.equals(result2);
    }


    public boolean verify2(BlsPoint publicKey, byte[] data, BlsPoint signature) {
        BlsPoint hashOfData = hashToCurveE1(data);
        BlsPoint basePointE2 = getBasePointE2();
        BlsPoint invertedSig = signature.negate();

        System.out.println("hash of Data: " + hashOfData.toString());
        System.out.println("basePointE2: " + basePointE2.toString());
        System.out.println("invertedSig: " + invertedSig.toString());
        System.out.println("publicKey: " + publicKey.toString());

        Fq12 pair1 = AltBn128Fq12Pairer.pair(((AltBn128PointWrapper)hashOfData).point, ((AltBn128Fq2PointWrapper)publicKey).point);
        //System.out.println("Pair 1: " + pair1);
        Fq12 pair2 = AltBn128Fq12Pairer.pair(((AltBn128PointWrapper)invertedSig).point, ((AltBn128Fq2PointWrapper)basePointE2).point);
        //System.out.println("Pair 2: " + pair2);

        Fq12 exponent = Fq12.one();
        exponent = exponent.multiply(pair1);
         exponent = exponent.multiply(pair2);
        Fq12 result2 = AltBn128Fq12Pairer.finalize(exponent);
        // System.out.println("Result2: " + result2);
        if (result2.equals(Fq12.one())) {
            return true;
        }
        return false;
    }

// Taken from here: https://github.com/PegaSysEng/pantheon/blob/master/ethereum/core/src/main/java/tech/pegasys/pantheon/ethereum/mainnet/precompiles/AltBN128PairingPrecompiledContract.java
    public boolean pair(final AltBn128Point p1, final AltBn128Fq2Point p2) {
        if (!p1.isOnCurve()) {
            // TODO should an exception be thrown?
            return false;
        }

        if (!p2.isOnCurve() /*|| !p2.isInGroup() */) {
            // TODO should an exception be thrown?
            return false;
        }

        // TODO this is written as if in a loop, as in the code from the Pantheon precompile
        Fq12 exponent = Fq12.one();
        exponent = exponent.multiply(AltBn128Fq12Pairer.pair(p1, p2));

        if (AltBn128Fq12Pairer.finalize(exponent).equals(Fq12.one())) {
            return true;
        }
        return false;
    }

}
