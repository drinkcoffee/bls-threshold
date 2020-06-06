// Copyright (C) 2018 ConsenSys
package tech.pegasys.poc.threshold.scheme;


import tech.pegasys.poc.threshold.util.Arrays;

import java.math.BigInteger;
import java.nio.ByteBuffer;

/**
 * Represents a single share.
 */
public class IntegerSecretShare {
    private BigInteger shareY;
    private BigInteger shareX;



    public IntegerSecretShare(BigInteger shareX, BigInteger shareY) {
        this.shareX = shareX;
        this.shareY = shareY;
    }


    public BigInteger getShareY() {
        return shareY;
    }

    public BigInteger getShareX() {
        return shareX;
    }



    public void updateY(BigInteger y) {
        this.shareY = y;
    }


    private static final int INT_LEN = 4;

    /**
     * Serialise the x and y values.
     *
     * @return Serialised x and y values.
     */
    public byte[] toBytes() {
        byte[] shareXBytes = this.shareX.toByteArray();
        int lenShareXBytes = shareXBytes.length;
        byte[] lenShareXBytesBytes = ByteBuffer.allocate(INT_LEN).putInt(lenShareXBytes).array();

        byte[] shareYBytes = this.shareY.toByteArray();
        int lenShareYBytes = shareYBytes.length;
        byte[] lenShareYBytesBytes = ByteBuffer.allocate(INT_LEN).putInt(lenShareYBytes).array();

        int totalLen = lenShareXBytesBytes.length + shareXBytes.length + lenShareYBytesBytes.length + shareYBytes.length;
        byte[] result = new byte[totalLen];

        int offset = Arrays.copyInto(lenShareXBytesBytes, result, 0);
        offset = Arrays.copyInto(shareXBytes, result, offset);
        offset = Arrays.copyInto(lenShareYBytesBytes, result, offset);
        offset = Arrays.copyInto(shareYBytes, result, offset);

        if (offset != totalLen) {
            throw new RuntimeException("Didn't copy all data into array");
        }
        return result;
    }


    /**
     * Deserialise the x and y values.
     *
     * @param from Serialised x and y values.
     */
    public static IntegerSecretShare fromBytes(byte[] from) {
        int offset = 0;
        byte[] lenShareXBytesBytes = new byte[INT_LEN];
        offset = Arrays.copyFrom(from, lenShareXBytesBytes, offset);
        int lenShareXBytes = ByteBuffer.wrap(lenShareXBytesBytes).getInt();

        byte[] shareXBytes = new byte[lenShareXBytes];
        offset = Arrays.copyFrom(from, shareXBytes, offset);
        BigInteger shareX = new BigInteger(1, shareXBytes);

        byte[] lenShareYBytesBytes = new byte[INT_LEN];
        offset = Arrays.copyFrom(from, lenShareYBytesBytes, offset);
        int lenShareYBytes = ByteBuffer.wrap(lenShareYBytesBytes).getInt();

        byte[] shareYBytes = new byte[lenShareYBytes];
        offset = Arrays.copyFrom(from, shareYBytes, offset);
        BigInteger shareY = new BigInteger(1, shareYBytes);

        return new IntegerSecretShare(shareX, shareY);
    }


    public String toString() {
        StringBuilder builder = new StringBuilder();
        return builder
                .append(", IntegerSecretShare: X: " + this.shareX)
                .append(", IntegerSecretShare: Y: " + this.shareY)
                .append("\n")
                .toString();
    }
}
