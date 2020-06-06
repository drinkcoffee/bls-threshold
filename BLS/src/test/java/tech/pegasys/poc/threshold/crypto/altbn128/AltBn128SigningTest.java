package tech.pegasys.poc.threshold.crypto.altbn128;


import org.junit.Test;
import tech.pegasys.pantheon.crypto.altbn128.AltBn128Fq12Pairer;
import tech.pegasys.pantheon.crypto.altbn128.AltBn128Point;
import tech.pegasys.pantheon.crypto.altbn128.Fq12;
import tech.pegasys.poc.threshold.crypto.BlsCryptoProvider;
import tech.pegasys.poc.threshold.crypto.BlsPoint;

import java.math.BigInteger;

/**
 * Check signing and verifying using the basic primitives.
 * Try using the public key on the E2 curve and on the E1 curve.
 */
public class AltBn128SigningTest {

    @Test
    public void signE1PubKeyE2() throws Exception {
        byte[] dataToBeSigned = new byte[]{0x01, 0x02};
        BigInteger privateKey = BigInteger.TEN;
        BlsCryptoProvider cryptoProvider = BlsCryptoProvider.getInstance(BlsCryptoProvider.CryptoProviderTypes.LOCAL_ALT_BN_128, BlsCryptoProvider.DigestAlgorithm.KECCAK256);

        BlsPoint publicKey = cryptoProvider.createPointE2(privateKey);

        BlsPoint hashOfData = cryptoProvider.hashToCurveE1(dataToBeSigned);

        BlsPoint signature = hashOfData.scalarMul(privateKey);

        BlsPoint basePointE2 = cryptoProvider.getBasePointE2();


        // TODO once this has been sorted out, have a verify signature function in the Wrapper.

        Fq12 pair1 = AltBn128Fq12Pairer.pair(((AltBn128PointWrapper)hashOfData).point, ((AltBn128Fq2PointWrapper)publicKey).point);
        System.out.println("Pair 1: " + pair1);
        Fq12 pair2 = AltBn128Fq12Pairer.pair(((AltBn128PointWrapper)signature).point, ((AltBn128Fq2PointWrapper)basePointE2).point);
        System.out.println("Pair 2: " + pair2);
        Fq12 pair3 = AltBn128Fq12Pairer.pair(((AltBn128PointWrapper)signature).point.negate(), ((AltBn128Fq2PointWrapper)basePointE2).point);
        System.out.println("Pair 3: " + pair3);


        Fq12 exponent;

        // Signature verification method 1: Compare the results.
        exponent = Fq12.one();
        exponent = exponent.multiply(pair1);
        Fq12 result1 = AltBn128Fq12Pairer.finalize(exponent);
        System.out.println("Result1: " + result1);

        exponent = Fq12.one();
        exponent = exponent.multiply(pair2);
        Fq12 result2 = AltBn128Fq12Pairer.finalize(exponent);
        System.out.println("Result2: " + result2);

        if (result1.equals(result2)) {
            System.out.println("Verified (standard method)!");
        }
        else {
            throw new Exception("Failed to Verify (standard method)!!");
        }

        // Signature verification method 2: Use the inverse of one of the points so it should equal zero.
        // This is what we would need to do for on-chain verification.
        exponent = Fq12.one();
        exponent = exponent.multiply(pair1);
        exponent = exponent.multiply(pair3);
        Fq12 result = AltBn128Fq12Pairer.finalize(exponent);
        System.out.println("Result: " + result);
        if (result.equals(Fq12.one())) {
            System.out.println("Verified (on chain method)!");
        }
        else {
            throw new Exception("Failed to Verify (on chain method)!!");
        }
    }



    @Test
    public void signE2PubKeyE1() throws Exception {
        byte[] dataToBeSigned = new byte[]{0x01, 0x02};
        BigInteger privateKey = BigInteger.TEN;
        BlsCryptoProvider cryptoProvider = BlsCryptoProvider.getInstance(BlsCryptoProvider.CryptoProviderTypes.LOCAL_ALT_BN_128, BlsCryptoProvider.DigestAlgorithm.KECCAK256);

        BlsPoint publicKey = cryptoProvider.createPointE1(privateKey);
        BlsPoint hashOfData = cryptoProvider.hashToCurveE2(dataToBeSigned);
        BlsPoint signature = hashOfData.scalarMul(privateKey);
        BlsPoint basePointE1 = cryptoProvider.getBasePointE1();


        // TODO once this has been sorted out, have a verify signature function in the Wrapper.

        Fq12 pair1 = AltBn128Fq12Pairer.pair(((AltBn128PointWrapper)publicKey).point, ((AltBn128Fq2PointWrapper)hashOfData).point);
        System.out.println("Pair 1: " + pair1);
        Fq12 pair2 = AltBn128Fq12Pairer.pair(((AltBn128PointWrapper)basePointE1).point, ((AltBn128Fq2PointWrapper)signature).point);
        System.out.println("Pair 2: " + pair2);
        Fq12 pair3 = AltBn128Fq12Pairer.pair(((AltBn128PointWrapper)basePointE1).point.negate(), ((AltBn128Fq2PointWrapper)signature).point);
        System.out.println("Pair 3: " + pair3);

        Fq12 exponent;

        // Signature verification method 1: Compare the results.
        exponent = Fq12.one();
        exponent = exponent.multiply(pair1);
        Fq12 result1 = AltBn128Fq12Pairer.finalize(exponent);
        System.out.println("Result1: " + result1);

        exponent = Fq12.one();
        exponent = exponent.multiply(pair2);
        Fq12 result2 = AltBn128Fq12Pairer.finalize(exponent);
        System.out.println("Result2: " + result2);

        if (result1.equals(result2)) {
            System.out.println("Verified (standard method)!");
        }
        else {
            throw new Exception("Failed to Verify (standard method)!!");
        }

        // Signature verification method 2: Use the inverse of one of the points so it should equal zero.
        // This is what we would need to do for on-chain verification.
        exponent = Fq12.one();
        exponent = exponent.multiply(pair1);
        exponent = exponent.multiply(pair3);
        Fq12 result = AltBn128Fq12Pairer.finalize(exponent);
        System.out.println("Result: " + result);
        if (result.equals(Fq12.one())) {
            System.out.println("Verified (on chain method)!");
        }
        else {
            throw new Exception("Failed to Verify (on chain method)!!");
        }
    }

}
