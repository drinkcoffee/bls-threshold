package tech.pegasys.poc.threshold.crypto.altbn128;


import org.junit.Test;
import tech.pegasys.poc.threshold.crypto.BlsCryptoProvider;
import tech.pegasys.poc.threshold.crypto.BlsPoint;
import tech.pegasys.poc.threshold.crypto.PointWrapperTest;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;

public class AltBn128PointWrapperTest extends PointWrapperTest {

    @Test
    public void loadStore() {
        loadStore(BlsCryptoProvider.CryptoProviderTypes.LOCAL_ALT_BN_128);
    }

}
