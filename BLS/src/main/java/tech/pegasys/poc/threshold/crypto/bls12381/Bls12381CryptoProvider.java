package tech.pegasys.poc.threshold.crypto.bls12381;

import org.apache.milagro.amcl.BLS381.*;


import tech.pegasys.poc.threshold.crypto.BlsPoint;
import tech.pegasys.poc.threshold.crypto.BlsCryptoProvider;
import tech.pegasys.poc.threshold.crypto.CryptoProviderBase;


import java.math.BigInteger;

public class Bls12381CryptoProvider extends CryptoProviderBase implements BlsCryptoProvider {
    //private static final String SECURITY_DOMAIN = "BLS12";

    public Bls12381CryptoProvider(BlsCryptoProvider.DigestAlgorithm alg) {
        super(alg);
    }

    public BigInteger modPrime(BigInteger val) {
        BIG q=new BIG(ROM.Modulus);
        DBIG dval = Bls12381Util.DBIGFromBigInteger(val);
        BIG modval = dval.mod(q);
        BigInteger biRet = Bls12381Util.BigIntegerFromBIG(modval);
        return(biRet);


    }

    public BigInteger getPrimeModulus() {
        BIG q=new BIG(ROM.Modulus);
        BigInteger biRet = Bls12381Util.BigIntegerFromBIG(q);
        return(biRet);
    }


    public BlsPoint createPointE1(BigInteger scalar) {
       org.apache.milagro.amcl.BLS381.ECP basedPoint = org.apache.milagro.amcl.BLS381.ECP.generator();
        BIG scBIG = Bls12381Util.BIGFromBigInteger(scalar);
        return new Bls12381PointWrapper(basedPoint.mul(scBIG));
    }

    public BlsPoint getBasePointE1() {
        org.apache.milagro.amcl.BLS381.ECP basedPoint = ECP.generator();
        return new Bls12381PointWrapper(basedPoint);
    }

    public BlsPoint createPointE2(BigInteger scalar) {
        ECP2 basedPoint = ECP2.generator();
        BIG bigScalar = Bls12381Util.BIGFromBigInteger(scalar);
        return new Bls12381Fq2PointWrapper(basedPoint.mul(bigScalar));
    }

    public BlsPoint getBasePointE2() {
        ECP2 basedPoint = ECP2.generator();
        return new Bls12381Fq2PointWrapper(basedPoint);
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

        ECP2 pk = ((Bls12381Fq2PointWrapper)publicKey).point;
        ECP hm = ((Bls12381PointWrapper)hashOfData).point;

        ECP2 g = ((Bls12381Fq2PointWrapper)basePointE2).point;
        ECP d = ((Bls12381PointWrapper)signature).point;
        d.neg();

        FP12 res1 = PAIR.ate2(g,d, pk,hm);
        FP12 v = PAIR.fexp(res1);

        boolean result = v.isunity();

        return result;
    }
    public boolean verify2(BlsPoint publicKey, byte[] data, BlsPoint signature) {
        return false;
    }


    public boolean pair(final ECP p1, final ECP2 p2) {

        // TODO this is written as if in a loop, as in the code from the Pantheon precompile

        FP12 pairResult = PAIR.ate(p2, p1);

        if (pairResult.isunity()) {
            return true;
        }
        return false;
    }

}
