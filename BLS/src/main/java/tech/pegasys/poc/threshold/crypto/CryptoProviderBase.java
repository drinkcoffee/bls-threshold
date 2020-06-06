package tech.pegasys.poc.threshold.crypto;


import com.google.common.base.Charsets;
import tech.pegasys.pantheon.crypto.Hash;
import tech.pegasys.pantheon.crypto.altbn128.AltBn128Fq12Pairer;
import tech.pegasys.pantheon.crypto.altbn128.Fq12;
import tech.pegasys.pantheon.util.bytes.Bytes32;
import tech.pegasys.pantheon.util.bytes.BytesValue;
import tech.pegasys.poc.threshold.crypto.altbn128.AltBn128Fq2PointWrapper;
import tech.pegasys.poc.threshold.crypto.altbn128.AltBn128PointWrapper;
import tech.pegasys.poc.threshold.util.Util;

import java.math.BigInteger;

/**
 * Base class of all crypto providers.
 */
abstract public class CryptoProviderBase implements BlsCryptoProvider {
    private static String IMPLEMENTATION_NAME = "THRES";
    private static String VERSION_STRING = "-v01";
    private static String ALGORITHM_BASE = "-a";
    private static int ALG_TYPE_FIXED_LENGTH = 5;

    public BlsCryptoProvider.DigestAlgorithm digestAlgorithm;

    public CryptoProviderBase(final BlsCryptoProvider.DigestAlgorithm alg) {
        this.digestAlgorithm = alg;
    }

    /**
     * Create a security domain separation parameter.
     * See https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04#page-7
     * section 2.2.5 for a discussion of Security Domain Separation.
     *
     * @param algType A fixed length string indicating the algorithm.
     * @return a byte array reflecting the security domain.
     */
    protected byte[] createSecuerityDomainPrefix(String algType) {
        if (algType.length() != ALG_TYPE_FIXED_LENGTH) {
            throw new Error("Invalid agorithm type string");
        }

//        String securityDomainString = IMPLEMENTATION_NAME + VERSION_STRING + ALGORITHM_BASE + algType;
        String securityDomainString = algType;
        return securityDomainString.getBytes(Charsets.UTF_8);
    }



    // TODO there is a lot of code duplicaiton between hashToCurveE1 and E2
    public BlsPoint hashToCurveE1(byte[] data) {
//        BytesValue dataBV1 = BytesValue.wrap(createSecuerityDomainPrefix(SECURITY_DOMAIN));
//        BytesValue dataBV1 = BytesValue.wrap(new byte[] {0x42, 0x4E, 0x31, 0x32, 0x38});
//        BytesValue dataBV2 = BytesValue.wrap(data);
//        BytesValue dataBV = BytesValues.concatenate(dataBV1, dataBV2);
        BytesValue dataBV = BytesValue.wrap(data);
        BlsPoint P = null;

        switch (this.digestAlgorithm) {
            case KECCAK256:
                Bytes32 digestedData = Hash.keccak256(dataBV);
                //System.out.println("digest: " + digestedData.toString());
                P = mapToCurveE1(digestedData.extractArray());
                //System.out.println("hash to curve E1:");
                P.store();
                break;
            default:
                throw new Error("not implemented yet!" + this.digestAlgorithm);
        }

        return P;
    }

    private static final BigInteger MAX_LOOP_COUNT = BigInteger.TEN;


    /**
     * Map a byte array to a point on the curve by converting the byte array
     * to an integer and then scalar multiplying the base point by the integer.
     */
    // The approach below is what can also work on-chain.
    // Alternative aproaches which might be better, but probably won't work on-chain:
    // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-04
    private BlsPoint mapToCurveE1(byte[] data) {
        BigInteger q = getPrimeModulus();

        BigInteger ctr = BigInteger.ZERO;

        BlsPoint p = null;

        while(true) {
            byte[] c = ctr.toByteArray();

//            /* Concatenate data with counter */
//            byte[] dc = new byte[data.length + c.length];
//            System.arraycopy(data, 0, dc, 0, data.length);
//            System.arraycopy(c, 0, dc, data.length, c.length);

            // Concatentation is hard on-chain. Instead, add one to the counter.
            BigInteger dc1 = new BigInteger(1, data);
            BigInteger x = dc1.add(ctr);


            // Convert back to a Big Integer mod q.
            // Indicate dc must be positive.
//            BigInteger x = new BigInteger(1, dc);
            x = x.mod(q);


            p = createPointE1(x);    // map to point

            // if map is valid, we are done
            if (!p.isAtInfinity()) {
                break;
            }

            // bump counter for next round, if necessary
            ctr = ctr.add(BigInteger.ONE);
            if (ctr.equals(MAX_LOOP_COUNT)) {
                throw new Error("Failed to map to point");
            }

        }

        return(p);
    }

    public BlsPoint hashToCurveE2(byte[] data) {
//        BytesValue dataBV1 = BytesValue.wrap(createSecuerityDomainPrefix(SECURITY_DOMAIN));
        BytesValue dataBV = BytesValue.wrap(data);
        //      BytesValue dataBV = BytesValues.concatenate(dataBV1, dataBV2);
        BlsPoint P = null;

        switch (this.digestAlgorithm) {
            case KECCAK256:
                Bytes32 digestedData = Hash.keccak256(dataBV);
                P = mapToCurveE2(digestedData.extractArray());
                break;
            default:
                throw new Error("not implemented yet!" + this.digestAlgorithm);
        }

        return P;
    }


    /**
     * Map a byte array to a point on the curve by converting the byte array
     * to an integer and then scalar multiplying the base point by the integer.
     */
    private BlsPoint mapToCurveE2(byte[] data) {
        BigInteger q = getPrimeModulus();

        BigInteger ctr = BigInteger.ZERO;

        BlsPoint p = null;

        while(true) {
            byte[] c = ctr.toByteArray();

            /* Concatenate data with counter */
            byte[] dc = new byte[data.length + c.length];
            System.arraycopy(data, 0, dc, 0, data.length);
            System.arraycopy(c, 0, dc, data.length, c.length);

            // Convert back to a Big Integer mod q.
            // Indicate dc must be positive.
            BigInteger x = new BigInteger(1, dc);
            x = x.mod(q);


            p = createPointE2(x);    // map to point

            // if map is valid, we are done
            if (!p.isAtInfinity()) {
                break;
            }

            // bump counter for next round, if necessary
            ctr = ctr.add(BigInteger.ONE);
            if (ctr.equals(MAX_LOOP_COUNT)) {
                throw new Error("Failed to map to point");
            }

        }

        return(p);
    }


    /**
     * Create a signature as a point on the E1 curve.
     *
     * @param privateKey Private key to sign data with.
     * @param data Data to be signed.
     * @return signature.
     */
    public BlsPoint sign(BigInteger privateKey, byte[] data) {
        BlsPoint hashOfData = hashToCurveE1(data);
        return hashOfData.scalarMul(privateKey);
    }


}
