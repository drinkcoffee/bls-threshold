package tech.pegasys.poc.threshold.protocol;

import tech.pegasys.pantheon.crypto.Hash;
import tech.pegasys.pantheon.util.bytes.Bytes32;
import tech.pegasys.pantheon.util.bytes.BytesValue;
import tech.pegasys.poc.threshold.crypto.BlsPoint;

import java.math.BigInteger;

// Contract which sits on the sidechain.
public class ThresholdKeyGenContract {
    private BigInteger[] nodeIds;
    private BlsPoint[][] coefficientPublicValues;
    private Bytes32[][] coefPublicPointCommitments;
    private int threshold;

    public ThresholdKeyGenContract(int threshold, int numberOfNodes) {
        this.threshold = threshold;
        this.nodeIds = new BigInteger[numberOfNodes];
        this.coefficientPublicValues = new BlsPoint[numberOfNodes][];
        this.coefPublicPointCommitments = new Bytes32[numberOfNodes][];
    }

    // Use NodeId to simulate the signing of a transaction / tracing the source of the transaction.
    public void setNodeId(int nodeNumber, BigInteger nodeId) throws Exception {
        if (this.nodeIds[nodeNumber] != null) {
            throw new Exception("Attempting to over write a node id");
        }
        nodeIds[nodeNumber] = nodeId;
    }

    public BigInteger[] getAllNodeIds() {
        return this.nodeIds;
    }

    public void setNodeCoefficientsCommitments(int nodeNumber, Bytes32[] coefPublicPointCommitments) throws Exception {
        if (coefPublicPointCommitments.length != this.threshold) {
            throw new Exception("Number of coefficient public value commitments did not match expected number of coefficients");
        }
        this.coefPublicPointCommitments[nodeNumber] = coefPublicPointCommitments;
    }

    public void setNodeCoefficientsPublicValues(int nodeNumber, BlsPoint[] coefPublicPoints) throws Exception {
        if (coefPublicPoints.length != this.threshold) {
            throw new Exception("Number of coefficient public values did not match expected number of coefficients");
        }

        // Check that the coefficient public points match what was committed to.
        // Reject requests to upload points which don't match the commitment.
        for (int i=0; i<coefPublicPoints.length; i++) {
            byte[] coefPubBytes = coefPublicPoints[i].store();
            Bytes32 commitment = Hash.keccak256(BytesValue.wrap(coefPubBytes));
            if (!this.coefPublicPointCommitments[nodeNumber][i].equals(commitment)) {
                throw new Exception("Public value did not match commitment");
            }
        }

        this.coefficientPublicValues[nodeNumber] = coefPublicPoints;
    }


    public BlsPoint getCoefficientPublicValue(int nodeNumberFrom, int coefNumber) {
        return this.coefficientPublicValues[nodeNumberFrom][coefNumber];
    }
    public BlsPoint[] getCoefficientPublicValues(int nodeNumberFrom) {
        return this.coefficientPublicValues[nodeNumberFrom];
    }

    // TODO I don't think a getting is needed.
    public Bytes32[] getCoefficientPublicValueCommitments(int nodeNumberFrom) {
        return this.coefPublicPointCommitments[nodeNumberFrom];
    }

}
