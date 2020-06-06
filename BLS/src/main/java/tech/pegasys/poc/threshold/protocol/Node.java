package tech.pegasys.poc.threshold.protocol;

import tech.pegasys.pantheon.crypto.Hash;
import tech.pegasys.pantheon.crypto.PRNGSecureRandom;
import tech.pegasys.pantheon.crypto.SECP256K1;
import tech.pegasys.pantheon.util.bytes.Bytes32;
import tech.pegasys.pantheon.util.bytes.BytesValue;
import tech.pegasys.poc.threshold.crypto.BlsCryptoProvider;
import tech.pegasys.poc.threshold.crypto.BlsPoint;
import tech.pegasys.poc.threshold.scheme.PointSecretShare;
import tech.pegasys.poc.threshold.scheme.ThresholdScheme;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Node {
    // Inter-node messages
    enum InterNodeMessages {
        REQUEST_SEND_SECRET_SHARES,
        SECRET_NODE_SHARE,
        REQUEST_SIGN
    }


    private int threshold;
    private int totalNumberOfNodes;
    private SecureRandom prng = new PRNGSecureRandom();


    private BigInteger[] myPartShares;
    private BigInteger[] receivedSecretShares;

    // This is the private key and public key which are used in devP2P and mining.
    private SECP256K1.KeyPair nodeKeyPair;
    private BigInteger nodeId;

    // Offset into listofNodes array.
    private int nodeNumber;
    private Node[] listOfNodes;

    private CrosschainCoordinationContract ccc;
    private ThresholdKeyGenContract thresholdContract;

    private BlsCryptoProvider cryptoProvider;


    private BigInteger privateKeyShare = null;

    private BlsPoint publicKey = null;

    private ThresholdScheme thresholdScheme;

    public Node(int myNodeNumber, int threshold, int totalNumberOfNodes) {
        this.nodeNumber = myNodeNumber;
        this.threshold = threshold;
        this.totalNumberOfNodes = totalNumberOfNodes;
        this.cryptoProvider = BlsCryptoProvider.getInstance(
                BlsCryptoProvider.CryptoProviderTypes.LOCAL_ALT_BN_128, BlsCryptoProvider.DigestAlgorithm.KECCAK256);

        this.receivedSecretShares = new BigInteger[this.totalNumberOfNodes];

        this.thresholdScheme = new ThresholdScheme(this.cryptoProvider, this.threshold, this.prng);

    }

    public void initNode(Node[] listOfNodes, CrosschainCoordinationContract ccc, ThresholdKeyGenContract thesholdContract) throws Exception {
        this.listOfNodes = listOfNodes;
        this.ccc = ccc;
        this.thresholdContract = thesholdContract;

        // Generate an ECC key pair to be used as Ethereum Node Key / Ethereum Node's account keys.
        this.nodeKeyPair = SECP256K1.KeyPair.generate();

        // Create a node id based on the public key.
        SECP256K1.PublicKey publicKey = this.nodeKeyPair.getPublicKey();
        byte[] encodedPublicKey = publicKey.getEncoded();
        BytesValue encodedPublicKeyBytesValue = BytesValue.wrap(encodedPublicKey);
        Bytes32 hash = Hash.keccak256(encodedPublicKeyBytesValue);
        byte[] hashBytes = hash.extractArray();
        BigInteger hashBigInt = new BigInteger(hashBytes);
        this.nodeId = this.cryptoProvider.modPrime(hashBigInt);
//        this.nodeId = BigInteger.valueOf(this.nodeNumber +1);

        // Publish Node Id.
        this.thresholdContract.setNodeId(this.nodeNumber, this.nodeId);
    }

    public BigInteger getNodeId() {
        return this.nodeId;
    }

    public int getNodeNumber() {
        return this.nodeNumber;
    }


    public void doKeyGeneration() throws Exception {
        // Generate and send node shares from this node.
        doKeyGenerationSingleNode();

        // Request all other nodes generate and send node shares.
        for (Node node: this.listOfNodes) {
            if (node != this) {
                sendPrivateMessage(InterNodeMessages.REQUEST_SEND_SECRET_SHARES, node);
            }
        }

        // Because all of the calls are synchronous in this PoC, all nodes should have their shares.
        getPublicKey();
        this.ccc.setPublicKey(this.publicKey);

    }


    private void doKeyGenerationSingleNode() throws Exception {
        generatePartsOfKeySharesAndPostPublicValues();
        for (Node node: this.listOfNodes) {
            if (node != this) {
                sendPrivateMessage(InterNodeMessages.SECRET_NODE_SHARE, node);
            }
        }
    }



    private void generatePartsOfKeySharesAndPostPublicValues() throws Exception {
        // Generate random coefficients.
        BigInteger[] coeffs = thresholdScheme.generateRandomCoefficients();

        // Get all X values.
        BigInteger[] xValues = this.thresholdContract.getAllNodeIds();

        // Generate the secret share parts (the y values).
        this.myPartShares = thresholdScheme.generateShares(xValues, coeffs);

        // Generate public values.
        BlsPoint[] coeffsPublicValues = new BlsPoint[coeffs.length];
        for (int i=0; i < coeffs.length; i++) {
            coeffsPublicValues[i] = this.cryptoProvider.createPointE2(coeffs[i]);
        }

        // Create and post the commitments to the coefficient public values.
        Bytes32[] commitments = new Bytes32[coeffs.length];
        for (int i=0; i<coeffs.length; i++) {
            byte[] coefPubBytes = coeffsPublicValues[i].store();
            commitments[i] = Hash.keccak256(BytesValue.wrap(coefPubBytes));
        }
        this.thresholdContract.setNodeCoefficientsCommitments(this.nodeNumber, commitments);


        // TODO only publish the public values after all of the commitments are posted.
        // Post public values of coefficient to threshold key gen contract.
        this.thresholdContract.setNodeCoefficientsPublicValues(this.nodeNumber, coeffsPublicValues);
    }

    // Get the node's private key share.
    // In a deployed system, this would not be exported from the node.
    public BigInteger getPrivateKeyShare() {
        if (this.privateKeyShare == null) {
            synchronized (this) {
                this.privateKeyShare = calculateMyPrivateKeyShare();
            }
        }
        return this.privateKeyShare;
    }

    // TODO, check that all of the shares were received.
    private BigInteger calculateMyPrivateKeyShare() {
        BigInteger privateKeyShareAcc = BigInteger.ZERO;
        for (int i=0; i < this.totalNumberOfNodes; i++) {
            BigInteger val;
            if (i == this.nodeNumber) {
                val = this.myPartShares[this.nodeNumber];
            } else {
                val = this.receivedSecretShares[i];
            }

            privateKeyShareAcc = privateKeyShareAcc.add(val);
            privateKeyShareAcc = this.cryptoProvider.modPrime(privateKeyShareAcc);
        }
        return privateKeyShareAcc;
    }


    public BlsPoint getPublicKey() {
        if (this.publicKey == null) {
            synchronized (this) {
                this.publicKey = calculatePublicKey();
            }
        }
        return this.publicKey;
    }


    /**
     * The public key is the sum of the constant coefficient for all curves.
     *
     * That is, the public key is the point for X=0. Given equations y = a x^3 + b x^2 + c x + d, the
     * x = 0 value is d. Summing the d values for all curves gives the public key.
     */

    private BlsPoint calculatePublicKey() {
        final int numCoeffs = this.threshold-1;
        BlsPoint yValue = null;

        for (int j = 0; j < this.totalNumberOfNodes; j++) {
            BlsPoint pubShare = this.thresholdContract.getCoefficientPublicValue(j, numCoeffs);
            if (yValue == null) {
                yValue = pubShare;
            } else {
                yValue = yValue.add(pubShare);
            }
        }

        return yValue;
    }


    public BlsPoint sign(byte[] data) throws Exception {
        // TODO a more complex implementation is needed, which sends to all nodes, and then only uses threshold of them
        BlsPoint[] sigShares = new BlsPoint[this.threshold];

        for (int i = 0; i < this.threshold; i++) {
            if (i == this.nodeNumber) {
                // Sign locally for the Coordinating Node.
                long startTime = System.nanoTime();
                sigShares[i] = localSign(data);
                long endTime = System.nanoTime();
                long duration = endTime - startTime;
                System.out.println(" ***** Local Sign: (in ns) " + duration + ", in us: " + duration/1000);
            }
            else {
                // Request another node sign the data.
                sigShares[i] = (BlsPoint) sendPrivateMessage(InterNodeMessages.REQUEST_SIGN, this.listOfNodes[i], data);
            }
        }


        // Add all of the points for each of the x values.
        BigInteger[] xValues = this.thresholdContract.getAllNodeIds();

        PointSecretShare[] shares = new PointSecretShare[this.threshold];
        for (int i = 0; i < this.threshold; i++) {
            shares[i] = new PointSecretShare(xValues[i], sigShares[i]);
        }

        // Do Lagrange interpolation to determine the group public key (the point for x=0).
        return this.thresholdScheme.calculateSecret(shares);
    }

    private BlsPoint localSign(byte[] data) {
        return this.cryptoProvider.sign(this.privateKeyShare, data);
    }


    public boolean verify(byte[] dataToBeVerified, BlsPoint signature) {
        return this.cryptoProvider.verify(getPublicKey(), dataToBeVerified, signature);
    }
    public boolean verify2(byte[] dataToBeVerified, BlsPoint signature) {
        return this.cryptoProvider.verify2(getPublicKey(), dataToBeVerified, signature);
    }

    // All of these messages should be signed.
    private Object sendPrivateMessage(InterNodeMessages type, Node destination) throws Exception {
        return sendPrivateMessage(type, destination, null);
    }
    private Object sendPrivateMessage(InterNodeMessages type, Node destination, Object data) throws Exception {
        switch (type) {
            case REQUEST_SEND_SECRET_SHARES:
                destination.receiveMessage(type, null, null);
                return null;
            case SECRET_NODE_SHARE:
                destination.receiveMessage(type, this.nodeNumber, this.myPartShares[destination.nodeNumber]);
                return null;
            case REQUEST_SIGN:
                return destination.receiveMessage(type, data, null);
            default:
                throw new Error("Not implemented yet!");
        }

    }

    private Object receiveMessage(InterNodeMessages type, Object anything1, Object anything2) throws Exception {
        switch (type) {
            case REQUEST_SEND_SECRET_SHARES:
                doKeyGenerationSingleNode();
                return null;
            case SECRET_NODE_SHARE:
                int senderNodeNumber = (Integer) anything1;
                BigInteger secretShare = (BigInteger) anything2;

                // Check that the secret share corresponds to a public value which is on the curve
                // defined by the coefficients the node published to the ThresholdKeyGenContract.
                BlsPoint[] coefPublicValues = this.thresholdContract.getCoefficientPublicValues(senderNodeNumber);
                BlsPoint publicKeyShare = this.cryptoProvider.createPointE2(secretShare);
                BlsPoint calculatedPublicKeyShare = this.thresholdScheme.generatePublicKeyShare(this.nodeId, coefPublicValues);

                if (!publicKeyShare.equals(calculatedPublicKeyShare)) {
                    throw new Error("Private share did not match coefficients.");
                }

                this.receivedSecretShares[senderNodeNumber] = secretShare;
                return null;
            case REQUEST_SIGN:
                return localSign((byte[])anything1);
            default:
                throw new Error("Not implemented yet!");
        }

    }
}
