package tech.pegasys.poc.threshold;


import tech.pegasys.poc.threshold.crypto.BlsPoint;
import tech.pegasys.poc.threshold.protocol.Node;

import java.io.FileWriter;
import java.math.BigInteger;
import java.util.Base64;
import java.util.Date;
import java.util.Properties;

// This is the main class is used to generate keys for use in the Subordinate View PoC.
public class PocMainGenerateKeys extends PocMain {

    private void storeStuff(BlsPoint[] otherNetworksPublicKeys, int[] sidechainIds, int sidechainId) throws Exception {
        BigInteger[] xValues = this.th.getAllNodeIds();
        BlsPoint pubKey = nodes[0].getPublicKey();
        byte[] pubKeyBytes = pubKey.store();
        String pubKeyBase64 = Base64.getEncoder().encodeToString(pubKeyBytes);


        for (Node node: this.nodes) {
            BigInteger privateKeyShare = node.getPrivateKeyShare();
            BigInteger nodeId = node.getNodeId();
            int nodeNumber = node.getNodeNumber();

            // I don't know if we are going to need all of this, but let's put it into the file as a starting point!
            Properties props = new Properties();
            props.setProperty("NodeNumber", Integer.toString(nodeNumber));
            props.setProperty("Threshold", Integer.toString(THRESHOLD));
            props.setProperty("NumNodes", Integer.toString(TOTAL_NUMBER_NODES));

            props.setProperty("NodePrivateKeyShare", privateKeyShare.toString());
            props.setProperty("NodeId", nodeId.toString());
            props.setProperty("SidechainPubKey", pubKeyBase64);

            for (int i = 0; i < otherNetworksPublicKeys.length; i++) {
                byte[] otherPubKeyBytes = otherNetworksPublicKeys[i].store();
                String otherPubKeyBase64 = Base64.getEncoder().encodeToString(otherPubKeyBytes);
                int otherSidechainId = sidechainIds[i];
                props.setProperty("SidechainPubKey" + otherSidechainId, otherPubKeyBase64);
            }


            for (int i = 0; i < xValues.length; i++) {
                props.setProperty("Xvalue" + i, xValues[i].toString());
            }

            String name = "sidechain" + sidechainId + "_node" + nodeNumber;
            String filename = name + ".properties";
            System.out.println("Saving file: " + "build/" + filename);
            FileWriter fw = new FileWriter("build/" + filename);
            props.store(fw, name);
        }



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




        PocMainGenerateKeys network1 = new PocMainGenerateKeys();
        network1.initNodes();
        network1.thresholdKeyGeneration();
        network1.checkPublicKey();
        BlsPoint network1PubKey = network1.nodes[0].getPublicKey();

        PocMainGenerateKeys network2 = new PocMainGenerateKeys();
        network2.initNodes();
        network2.thresholdKeyGeneration();
        network2.checkPublicKey();
        BlsPoint network2PubKey = network2.nodes[0].getPublicKey();

        PocMainGenerateKeys network3 = new PocMainGenerateKeys();
        network3.initNodes();
        network3.thresholdKeyGeneration();
        network3.checkPublicKey();
        BlsPoint network3PubKey = network3.nodes[0].getPublicKey();


        network1.storeStuff(new BlsPoint[]{network2PubKey, network3PubKey}, new int[]{22,33}, 11);
        network2.storeStuff(new BlsPoint[]{network1PubKey, network3PubKey}, new int[]{11,33}, 22);
        network3.storeStuff(new BlsPoint[]{network1PubKey, network2PubKey}, new int[]{11,22}, 33);

        System.out.println();
        System.out.println(" Date: " + (new Date().toString()));
        System.out.println("Test: End");
    }
}
