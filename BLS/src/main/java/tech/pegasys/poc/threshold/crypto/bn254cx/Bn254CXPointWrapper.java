package tech.pegasys.poc.threshold.crypto.bn254cx;


import org.apache.milagro.amcl.BN254CX.BIG;
import org.apache.milagro.amcl.BN254CX.ECP;
import tech.pegasys.poc.threshold.crypto.BlsPoint;

import java.math.BigInteger;

public class Bn254CXPointWrapper implements BlsPoint{

     ECP point;

    Bn254CXPointWrapper(ECP point) {
        this.point = point;

    }


    // Add a point to this point.
    public Bn254CXPointWrapper add(BlsPoint obj) {
        this.point.add(((Bn254CXPointWrapper)obj).point);
        return new Bn254CXPointWrapper(this.point);
    }

    // Multiple this point by a scalar.
    public Bn254CXPointWrapper scalarMul(BigInteger scalar) {
        BIG scBig = Bn254CXUtil.BIGFromBigInteger(scalar);
        return new Bn254CXPointWrapper(this.point.mul(scBig));
    }



    // Return true if this point is the point at infinity.
    public boolean isAtInfinity() {
        return this.point.is_infinity();
    }

    @Override
    public BlsPoint negate() {
        ECP p;
        p = new ECP();
        this.point.copy(p);
        p.neg();
        return new Bn254CXPointWrapper(p);
    }


    private static final int WORD_LEN = BIG.MODBYTES;
    public static final int STORED_LEN = 2*WORD_LEN;
    public byte[] store() {
        BIG x = this.point.getX();
        byte xBytes[] = new byte[BIG.MODBYTES];
        x.tobytearray(xBytes, 0);

        BIG y = this.point.getY();
        byte yBytes[] = new byte[BIG.MODBYTES];
        y.tobytearray(yBytes, 0);

        byte[] output = new byte[STORED_LEN];

        // All of the values should be 256 bits long. However, it is possible that some
        // could have leading zeros, in which case we should zero fill.
        int len = xBytes.length;
        // TODO is this the correct endianess ???
        System.arraycopy(xBytes, 0, output, WORD_LEN - len, len);

        len = yBytes.length;
        // TODO is this the correct endianess ???
        System.arraycopy(yBytes, 0, output, STORED_LEN - len, len);

        return output;
    }

    public static Bn254CXPointWrapper load(byte[] data) {
        if (data.length != STORED_LEN) {
            throw new Error("BLS12-381 Point data incorrect length. Should be " + STORED_LEN + ", is " + data.length);
        }

        byte[] xBytes = new byte[WORD_LEN];
        System.arraycopy(data, 0, xBytes, 0, WORD_LEN);

        byte[] yBytes = new byte[WORD_LEN];
        System.arraycopy(data, WORD_LEN, yBytes, 0, WORD_LEN);

        BIG x = Bn254CXUtil.BIGFromBigInteger(new BigInteger(xBytes));
        BIG y = Bn254CXUtil.BIGFromBigInteger(new BigInteger(yBytes));
        ECP point = new ECP(x, y);

        return new Bn254CXPointWrapper(point);
    }


    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Bn254CXPointWrapper)) {
            return false;
        }

        return  this.point.equals(((Bn254CXPointWrapper) obj).point);
    }

    @Override
    public int hashCode() {
        return this.point.hashCode();
    }

    @Override
    public String toString() {
        return this.point.toString();
    }


}