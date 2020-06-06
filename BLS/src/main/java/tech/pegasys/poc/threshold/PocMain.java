package tech.pegasys.poc.threshold;


import org.apache.milagro.amcl.BLS381.BIG;
import tech.pegasys.poc.threshold.crypto.BlsCryptoProvider;
import tech.pegasys.poc.threshold.crypto.BlsPoint;
import tech.pegasys.poc.threshold.protocol.CrosschainCoordinationContract;
import tech.pegasys.poc.threshold.protocol.Node;
import tech.pegasys.poc.threshold.protocol.ThresholdKeyGenContract;
import tech.pegasys.poc.threshold.scheme.IntegerSecretShare;
import tech.pegasys.poc.threshold.scheme.ThresholdScheme;
import tech.pegasys.poc.threshold.crypto.bls12381.Bls12381Util;

import java.io.FileWriter;
import java.math.BigInteger;
import java.util.Date;

// This is the main class for running through a simple scenario.
public class PocMain {
    static final int THRESHOLD = 3;
    static final int TOTAL_NUMBER_NODES = 5;

    static final int COORDINATING_NODE = 0;


    private static BlsCryptoProvider.CryptoProviderTypes cryptoType = BlsCryptoProvider.CryptoProviderTypes.LOCAL_ALT_BN_128;

    Node[] nodes;
    CrosschainCoordinationContract ccc;
    ThresholdKeyGenContract th;


    static byte[] DATA = new byte[]{0x01, 0x02, 0x03, 0x04};

    // Initialise the network of nodes.
    void initNodes() throws Exception {
        this.ccc = new CrosschainCoordinationContract();
        this.th = new ThresholdKeyGenContract(THRESHOLD, TOTAL_NUMBER_NODES);

        this.nodes = new Node[TOTAL_NUMBER_NODES];
        for (int i=0; i < TOTAL_NUMBER_NODES; i++) {
            this.nodes[i] = new Node(i, THRESHOLD, TOTAL_NUMBER_NODES);
        }

        for (Node node: this.nodes) {
            node.initNode(this.nodes, this.ccc, this.th);
        }
    }


    void thresholdKeyGeneration() throws Exception {
        // Any node can lead the key generation process.
        // TODO: How to determine which node should trigger a key generation sequence /  how to do this.
        this.nodes[COORDINATING_NODE].doKeyGeneration();

    }

    void checkPublicKey() throws Exception {
        // Calculate the group private key.
        // In a real situation, this private key is never combined.

        // Add all of the points for each of the x values.
        BigInteger[] xValues = this.th.getAllNodeIds();

        for (int i = 0; i < TOTAL_NUMBER_NODES; i++) {
            IntegerSecretShare share = new IntegerSecretShare(xValues[i], this.nodes[i].getPrivateKeyShare());
            System.out.println("Share: " + share);
        }
        IntegerSecretShare[] shares = new IntegerSecretShare[THRESHOLD];
        for (int i = 0; i < THRESHOLD; i++) {
            shares[i] = new IntegerSecretShare(xValues[i], this.nodes[i].getPrivateKeyShare());
        }

        BlsCryptoProvider cryptoProvider = BlsCryptoProvider.getInstance(cryptoType, BlsCryptoProvider.DigestAlgorithm.KECCAK256);
        ThresholdScheme thresholdScheme = new ThresholdScheme(cryptoProvider, THRESHOLD);

        // Do Lagrange interpolation to determine the group private key (the point for x=0).
        BigInteger privateKey = thresholdScheme.calculateSecret(shares);
        System.out.println("Private Key: " + privateKey);

        BlsPoint shouldBePublicKey = cryptoProvider.createPointE2(privateKey);
        System.out.println("Public Key derived from private key: " + shouldBePublicKey);

        BlsPoint pubKey = this.nodes[0].getPublicKey();
        System.out.println("Public Key derived from public shares: " + pubKey);

        if (shouldBePublicKey.equals(pubKey)) {
            System.out.println("Key generation worked!!!!!");
        }
        else {
            throw new Exception("Private key and public key did not match!");
        }

        BlsCryptoProvider cryptoProviderBls12 = BlsCryptoProvider.getInstance(cryptoType, BlsCryptoProvider.DigestAlgorithm.KECCAK256);
        ThresholdScheme thresholdSchemeBls12 = new ThresholdScheme(cryptoProvider, THRESHOLD);

        // Do Lagrange interpolation to determine the group private key (the point for x=0).
        BigInteger privateKeyBls12 = thresholdSchemeBls12.calculateSecret(shares);
        System.out.println("Bls12 Private Key: " + privateKeyBls12);

        BlsPoint shouldBePublicKeyBls12 = cryptoProvider.createPointE2(privateKey);
        System.out.println("Bls12 Public Key derived from private key: " + shouldBePublicKeyBls12);

        BlsPoint pubKeyBls12 = this.nodes[0].getPublicKey();
        System.out.println("Bls12Public Key derived from public shares: " + pubKeyBls12);

        if (shouldBePublicKeyBls12.equals(pubKeyBls12)) {
            System.out.println("Key generation worked!!!!!");
        }
        else {
            throw new Exception("Private key and public key did not match!");
        }


    }


    BlsPoint thresholdSign(byte[] toBeSigned) throws Exception {
        return this.nodes[COORDINATING_NODE].sign(toBeSigned);
    }

    boolean thresholdVerify(byte[] toBeVerified, BlsPoint signature) {
        return this.nodes[COORDINATING_NODE].verify(toBeVerified, signature);

    }




    public static void main(String[] args) throws Exception {

        // Make stdout and stderr one stream. Have them both non-buffered.
        // What this means is that if an error or exception stack trace is thrown,
        // it will be shown in the context of the other output.
        System.setOut(System.err);

        System.out.println("Test: Start");
        System.out.println(" Date: " + (new Date().toString()));
        System.out.println();

        if (THRESHOLD > TOTAL_NUMBER_NODES) {
            throw new Exception("Configuration Error: THRESHOLD > TOTAL_NUMBER_NODES !");
        }




        PocMain test = new PocMain();
        test.initNodes();
        test.thresholdKeyGeneration();

        test.checkPublicKey();

        BlsPoint signature = test.thresholdSign(DATA);
        boolean verified = test.thresholdVerify(DATA, signature);

        System.out.println("Signature verified: " + verified);

        System.out.println();
        System.out.println(" Date: " + (new Date().toString()));
        System.out.println("Test: End");



    }

}
