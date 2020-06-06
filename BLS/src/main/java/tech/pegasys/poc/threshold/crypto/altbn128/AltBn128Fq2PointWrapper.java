package tech.pegasys.poc.threshold.crypto.altbn128;

import tech.pegasys.pantheon.crypto.altbn128.*;
import tech.pegasys.pantheon.util.bytes.BytesValue;
import tech.pegasys.poc.threshold.crypto.BlsPoint;

import java.math.BigInteger;

// TODO getting a class cast exception if BlsPublicKey is not added here -???
public class AltBn128Fq2PointWrapper implements BlsPoint {

    AltBn128Fq2Point point;

    AltBn128Fq2PointWrapper(AltBn128Fq2Point point) {
        this.point = point;

    }



    // Add a point to this point.
    public BlsPoint add(BlsPoint obj) {
        if (!(obj instanceof AltBn128Fq2PointWrapper)) {
            throw new RuntimeException("incorrect point addition with Bn128 point");
        }
        AltBn128Fq2Point p = this.point.add(((AltBn128Fq2PointWrapper)obj).point);
        return new AltBn128Fq2PointWrapper(p);
    }

    // Multiple this point by a scalar.
    public BlsPoint scalarMul(BigInteger scalar) {
        return new AltBn128Fq2PointWrapper(this.point.multiply(scalar));
    }



    // Return true if this point is the point at infinity.
    public boolean isAtInfinity() {
        return this.point.isInfinity();
    }

    public BlsPoint negate() {
        return new AltBn128Fq2PointWrapper(this.point.negate());
    }


    private static final int WORD_LEN = 32;
    public static final int STORED_LEN = WORD_LEN+WORD_LEN+WORD_LEN+WORD_LEN;
    public byte[] store() {
        Fq2 x = this.point.getX();
        Fq[] xCoeffs = x.getCoefficients();
        if (xCoeffs.length != 2) {
            // Should just be real and imaginary.
            throw new Error("x unexpected number of coefficients");
        }

        BytesValue bytesV = xCoeffs[0].toBytesValue();
        System.out.println("x[0]: " + bytesV.toString());
        byte[] xBytesReal = bytesV.extractArray();
        bytesV = xCoeffs[1].toBytesValue();
        System.out.println("x[1]: " + bytesV.toString());
        byte[] xBytesImaginary = bytesV.extractArray();

        Fq2 y = this.point.getY();
        Fq[] yCoeffs = y.getCoefficients();
        if (yCoeffs.length != 2) {
            // Should just be real and imaginary.
            throw new Error("y unexpected number of coefficients");
        }

        bytesV = yCoeffs[0].toBytesValue();
        System.out.println("y[0]: " + bytesV.toString());
        byte[] yBytesReal = bytesV.extractArray();
        bytesV = yCoeffs[1].toBytesValue();
        System.out.println("y[1]: " + bytesV.toString());
        byte[] yBytesImaginary = bytesV.extractArray();

        byte[] output = new byte[STORED_LEN];

        // All of the values should be 256 bits long. However, it is possible that some
        // could have leading zeros, in which case we should zero fill.
        int len = xBytesImaginary.length;
        System.arraycopy(xBytesImaginary, 0, output, WORD_LEN - len, len);
        len = xBytesReal.length;
        System.arraycopy(xBytesReal, 0, output, WORD_LEN + WORD_LEN - len, len);
        len = yBytesImaginary.length;
        System.arraycopy(yBytesImaginary, 0, output, WORD_LEN + WORD_LEN + WORD_LEN - len, len);
        len = yBytesReal.length;
        System.arraycopy(yBytesReal, 0, output, STORED_LEN - len, len);

        return output;
    }

    public static AltBn128Fq2PointWrapper load(byte[] data) {
        if (data.length != STORED_LEN) {
            throw new Error("Bn128Fq2 Point data incorrect length. Should be " + STORED_LEN + ", is " + data.length);
        }

        byte[] xBytesImaginary = new byte[WORD_LEN];
        System.arraycopy(data, 0, xBytesImaginary, 0, WORD_LEN);
        byte[] xBytesReal = new byte[WORD_LEN];
        System.arraycopy(data, WORD_LEN, xBytesReal, 0, WORD_LEN);
        byte[] yBytesImaginary = new byte[WORD_LEN];
        System.arraycopy(data, WORD_LEN+WORD_LEN, yBytesImaginary, 0, WORD_LEN);
        byte[] yBytesReal = new byte[WORD_LEN];
        System.arraycopy(data, WORD_LEN+WORD_LEN+WORD_LEN, yBytesReal, 0, WORD_LEN);

        Fq2 x = Fq2.create(new BigInteger(xBytesReal), new BigInteger(xBytesImaginary));
        Fq2 y = Fq2.create(new BigInteger(yBytesReal), new BigInteger(yBytesImaginary));
        AltBn128Fq2Point point = new AltBn128Fq2Point(x, y);

        return new AltBn128Fq2PointWrapper(point);
    }


    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AltBn128Fq2PointWrapper)) {
            return false;
        }

        return  this.point.equals(((AltBn128Fq2PointWrapper) obj).point);
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
