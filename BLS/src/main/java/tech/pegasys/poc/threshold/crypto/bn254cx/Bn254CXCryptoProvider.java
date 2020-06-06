package tech.pegasys.poc.threshold.crypto.bn254cx;

import org.apache.milagro.amcl.BN254CX.BIG;
import org.apache.milagro.amcl.BN254CX.DBIG;
import org.apache.milagro.amcl.BN254CX.ECP;
import org.apache.milagro.amcl.BN254CX.ECP2;
import org.apache.milagro.amcl.BN254CX.FP12;
import org.apache.milagro.amcl.BN254CX.PAIR;
import org.apache.milagro.amcl.BN254CX.ROM;
import tech.pegasys.pantheon.crypto.Hash;
import tech.pegasys.pantheon.util.bytes.Bytes32;
import tech.pegasys.pantheon.util.bytes.BytesValue;
import tech.pegasys.poc.threshold.crypto.BlsCryptoProvider;
import tech.pegasys.poc.threshold.crypto.BlsPoint;
import tech.pegasys.poc.threshold.crypto.CryptoProviderBase;

import java.math.BigInteger;

public class Bn254CXCryptoProvider extends CryptoProviderBase implements BlsCryptoProvider {
//    private static final String SECURITY_DOMAIN = "BN254";

    public Bn254CXCryptoProvider(DigestAlgorithm alg) {
        super(alg);
    }

    public BigInteger modPrime(BigInteger val) {
        BIG q=new BIG(ROM.Modulus);
        DBIG dval = Bn254CXUtil.DBIGFromBigInteger(val);
        BIG modval = dval.mod(q);
        BigInteger biRet = Bn254CXUtil.BigIntegerFromBIG(modval);
        return(biRet);


    }

    public BigInteger getPrimeModulus() {
        BIG q=new BIG(ROM.Modulus);
        BigInteger biRet = Bn254CXUtil.BigIntegerFromBIG(q);
        return(biRet);
    }


    public BlsPoint createPointE1(BigInteger scalar) {
       ECP basedPoint = ECP.generator();
        BIG scBIG = Bn254CXUtil.BIGFromBigInteger(scalar);
        return new Bn254CXPointWrapper(basedPoint.mul(scBIG));
    }

    public BlsPoint getBasePointE1() {
        ECP basedPoint = ECP.generator();
        return new Bn254CXPointWrapper(basedPoint);
    }


    public BlsPoint createPointE2(BigInteger scalar) {
        ECP2 basedPoint = ECP2.generator();
        BIG bigScalar = Bn254CXUtil.BIGFromBigInteger(scalar);
        return new Bn254CXFq2PointWrapper(basedPoint.mul(bigScalar));
    }

    public BlsPoint getBasePointE2() {
        ECP2 basedPoint = ECP2.generator();
        return new Bn254CXFq2PointWrapper(basedPoint);
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

        ECP2 pk = ((Bn254CXFq2PointWrapper)publicKey).point;
        ECP hm = ((Bn254CXPointWrapper)hashOfData).point;

        ECP2 g = ((Bn254CXFq2PointWrapper)basePointE2).point;
        ECP d = ((Bn254CXPointWrapper)signature).point;
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
