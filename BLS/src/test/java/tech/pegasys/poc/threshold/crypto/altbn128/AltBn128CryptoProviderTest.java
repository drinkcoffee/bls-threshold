package tech.pegasys.poc.threshold.crypto.altbn128;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import tech.pegasys.poc.threshold.crypto.BlsCryptoProvider;
import tech.pegasys.poc.threshold.crypto.BlsPoint;
import tech.pegasys.poc.threshold.crypto.CryptoProviderTest;

import java.math.BigInteger;

public class AltBn128CryptoProviderTest extends CryptoProviderTest {

    @Test
    public void signVerifyHappyCase() {
        signVerifyHappyCase(BlsCryptoProvider.CryptoProviderTypes.LOCAL_ALT_BN_128);
    }

    @Test
    public void signVerifyBadVerifyData() {
        signVerifyBadVerifyData(BlsCryptoProvider.CryptoProviderTypes.LOCAL_ALT_BN_128);
    }

    @Test
    public void signVerifyBadPublicKey() {
        signVerifyBadPublicKey(BlsCryptoProvider.CryptoProviderTypes.LOCAL_ALT_BN_128);
    }

}
