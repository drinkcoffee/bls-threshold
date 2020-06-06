package tech.pegasys.poc.threshold.crypto;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;

public class CryptoProviderTest {

    public void signVerifyHappyCase(BlsCryptoProvider.CryptoProviderTypes type) {
        byte[] dataToBeSigned = new byte[] {0x01, 0x02, 0x03};
        BigInteger privateKey = BigInteger.TEN;

        BlsCryptoProvider cryptoProvider = BlsCryptoProvider.getInstance(type, BlsCryptoProvider.DigestAlgorithm.KECCAK256);
        BlsPoint pubKey = cryptoProvider.createPointE2(privateKey);

        BlsPoint signature = cryptoProvider.sign(privateKey, dataToBeSigned);
        boolean verified = cryptoProvider.verify(pubKey, dataToBeSigned, signature);
        assertThat(verified).isTrue();
    }

    public void signVerifyBadVerifyData(BlsCryptoProvider.CryptoProviderTypes type) {
        byte[] dataToBeSigned = new byte[] {0x01, 0x02, 0x03};
        byte[] dataToBeVerified = new byte[] {0x01, 0x02, 0x04};
        BigInteger privateKey = BigInteger.TEN;

        BlsCryptoProvider cryptoProvider = BlsCryptoProvider.getInstance(type, BlsCryptoProvider.DigestAlgorithm.KECCAK256);
        BlsPoint pubKey = cryptoProvider.createPointE2(privateKey);

        BlsPoint signature = cryptoProvider.sign(privateKey, dataToBeSigned);
        boolean verified = cryptoProvider.verify(pubKey, dataToBeVerified, signature);
        assertThat(verified).isFalse();
    }

    public void signVerifyBadPublicKey(BlsCryptoProvider.CryptoProviderTypes type) {
        byte[] dataToBeSigned = new byte[] {0x01, 0x02, 0x03};
        BigInteger privateKey = BigInteger.TEN;

        BlsCryptoProvider cryptoProvider = BlsCryptoProvider.getInstance(type, BlsCryptoProvider.DigestAlgorithm.KECCAK256);
        BlsPoint pubKey = cryptoProvider.getBasePointE2();

        BlsPoint signature = cryptoProvider.sign(privateKey, dataToBeSigned);
        boolean verified = cryptoProvider.verify(pubKey, dataToBeSigned, signature);
        assertThat(verified).isFalse();
    }

}
