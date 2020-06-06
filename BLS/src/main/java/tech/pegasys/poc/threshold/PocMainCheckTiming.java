package tech.pegasys.poc.threshold;


import tech.pegasys.poc.threshold.crypto.BlsCryptoProvider;
import tech.pegasys.poc.threshold.crypto.BlsPoint;
import tech.pegasys.poc.threshold.crypto.bn254.Bn254PointWrapper;
import tech.pegasys.poc.threshold.crypto.bn254cx.Bn254CXPointWrapper;
import tech.pegasys.poc.threshold.protocol.CrosschainCoordinationContract;
import tech.pegasys.poc.threshold.protocol.Node;
import tech.pegasys.poc.threshold.protocol.ThresholdKeyGenContract;
import tech.pegasys.poc.threshold.scheme.IntegerSecretShare;
import tech.pegasys.poc.threshold.scheme.ThresholdScheme;
import tech.pegasys.poc.threshold.util.Util;

import java.math.BigInteger;
import java.util.Date;

// This is the main class for running through a simple scenario.
public class PocMainCheckTiming {


    private static BlsCryptoProvider.CryptoProviderTypes cryptoType = BlsCryptoProvider.CryptoProviderTypes.LOCAL_ALT_BN_128;


    public static void test(BlsCryptoProvider cryptoProvider) {
        byte[] data = new byte[]{0x01, 0x02, 0x03, 0x04};

        //BigInteger privateKey = BigInteger.ONE;
        BigInteger privateKey = BigInteger.valueOf(0x7fffffff);

        int testIterations = 100;
        int trials = 10;
        long start, end, ave;
        String testName;

        // Public key is an E2 point.
        BlsPoint publicKey = cryptoProvider.createPointE2(privateKey);

        // Signature is an E1 point.
        BlsPoint signature = cryptoProvider.sign(privateKey, data);

        boolean verified = cryptoProvider.verify(publicKey, data, signature);

        System.out.println("Signature verified: " + verified);


        testName = "Scalar Multiply: E1";
        System.out.println(testName);
        for (int j=0; j < trials; j++) {
            start = System.nanoTime();
            for (int i = 0; i< testIterations; i++) {
                cryptoProvider.createPointE1(privateKey);
            }
            end = System.nanoTime();
            ave = (end - start)/testIterations;
            System.err.println(testName + ": " + ave + " ns, " + ave/1000 + " us, " + ave/1000000 + " ms");
        }

        testName = "Scalar Multiply: E2";
        System.out.println(testName);
        for (int j=0; j < trials; j++) {
            start = System.nanoTime();
            for (int i = 0; i< testIterations; i++) {
                cryptoProvider.createPointE2(privateKey);
            }
            end = System.nanoTime();
            ave = (end - start)/testIterations;
            System.err.println(testName + ": " + ave + " ns, " + ave/1000 + " us, " + ave/1000000 + " ms");
        }

        System.out.println("Sign is two E1 scalar multiplies");


        testName = "Verify: 2 pairing and hash to point for E1";
        System.out.println(testName);
//        for (int j=0; j < 2; j++) {
            for (int j=0; j < trials; j++) {
            start = System.nanoTime();
            for (int i = 0; i< testIterations; i++) {
                cryptoProvider.verify(publicKey, data, signature);
            }
            end = System.nanoTime();
            ave = (end - start)/testIterations;
            System.err.println(testName + ": " + ave + " ns, " + ave/1000 + " us, " + ave/1000000 + " ms");
        }
    }


    public static void check() {
        BlsCryptoProvider p1 = BlsCryptoProvider.getInstance(BlsCryptoProvider.CryptoProviderTypes.LOCAL_ALT_BN_128, BlsCryptoProvider.DigestAlgorithm.KECCAK256);
        BlsCryptoProvider p2 = BlsCryptoProvider.getInstance(BlsCryptoProvider.CryptoProviderTypes.BN254CX, BlsCryptoProvider.DigestAlgorithm.KECCAK256);
        BlsCryptoProvider p3 = BlsCryptoProvider.getInstance(BlsCryptoProvider.CryptoProviderTypes.BN254, BlsCryptoProvider.DigestAlgorithm.KECCAK256);
        byte[] data = new byte[]{0x01, 0x02, 0x03, 0x04};

        //BigInteger privateKey = BigInteger.ONE;
        BigInteger privateKey = BigInteger.valueOf(0x7fffffff);


        System.out.println("BN128");
        Util.printBuffer(p1.getBasePointE2().store());
        System.out.println("BN254");
        Util.printBuffer(p2.getBasePointE2().store());
        System.out.println("BN254CX");
        Util.printBuffer(p3.getBasePointE2().store());


        // Public key is an E2 point.
        BlsPoint publicKey = p2.createPointE2(privateKey);

        // Signature is an E1 point.
        System.out.println("BN128 - Local");
        BlsPoint signature = p1.sign(privateKey, data);
        Util.printBuffer(signature.store());

        System.out.println("BN254CX - Milagro");
        BlsPoint signature1 = p2.sign(privateKey, data);
        Util.printBuffer(signature1.store());

        System.out.println("BN254 - Milagro");
        BlsPoint signature2 = p3.sign(privateKey, data);
        Util.printBuffer(signature2.store());

        byte[] sigData = signature.store();
        BlsPoint sig2 = Bn254CXPointWrapper.load(sigData);
        boolean verified = p2.verify(publicKey, data, sig2);
        System.out.println("Signature verified: " + verified);

    }
    public static void main(String[] args) throws Exception {

        // Make stdout and stderr one stream. Have them both non-buffered.
        // What this means is that if an error or exception stack trace is thrown,
        // it will be shown in the context of the other output.
        System.setOut(System.err);

        System.out.println("Test: Start");
        System.out.println(" Date: " + (new Date().toString()));
        System.out.println();

//        check();


        System.err.println("BN128");
//        test(BlsCryptoProvider.getInstance(BlsCryptoProvider.CryptoProviderTypes.LOCAL_ALT_BN_128, BlsCryptoProvider.DigestAlgorithm.KECCAK256));

        System.err.println("BN254");
        test(BlsCryptoProvider.getInstance(BlsCryptoProvider.CryptoProviderTypes.BN254, BlsCryptoProvider.DigestAlgorithm.KECCAK256));

        System.err.println("BN254CX");
        test(BlsCryptoProvider.getInstance(BlsCryptoProvider.CryptoProviderTypes.BN254CX, BlsCryptoProvider.DigestAlgorithm.KECCAK256));

        System.err.println("BN12-381");
        test(BlsCryptoProvider.getInstance(BlsCryptoProvider.CryptoProviderTypes.LOCAL_BLS12_381, BlsCryptoProvider.DigestAlgorithm.KECCAK256));

        System.out.println();
        System.out.println(" Date: " + (new Date().toString()));
        System.out.println("Test: End");


    }

}
