package tech.pegasys.poc.threshold.crypto;


import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;

public class PointWrapperTest {

    public void loadStore(BlsCryptoProvider.CryptoProviderTypes type) {
        BigInteger privateKey = BigInteger.TEN;
        BlsCryptoProvider cryptoProvider = BlsCryptoProvider.getInstance(type, BlsCryptoProvider.DigestAlgorithm.KECCAK256);
        BlsPoint point = cryptoProvider.createPointE1(privateKey);

        byte[] data = point.store();
        BlsPoint newPoint = BlsPoint.load(data);

        assertThat(newPoint.equals(point)).isTrue();
    }

}
