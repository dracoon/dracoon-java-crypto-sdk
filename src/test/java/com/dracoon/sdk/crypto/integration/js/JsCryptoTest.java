package com.dracoon.sdk.crypto.integration.js;

import com.dracoon.sdk.crypto.error.CryptoSystemException;
import com.dracoon.sdk.crypto.error.InvalidKeyPairException;
import com.dracoon.sdk.crypto.error.UnknownVersionException;
import org.junit.Test;

public class JsCryptoTest extends com.dracoon.sdk.crypto.integration.CryptoTest {

    @Override
    public String data(String subPath) {
        return JsTestHelper.data(subPath);
    }

    @Override
    public String file(String subPath) {
        return JsTestHelper.file(subPath);
    }

    @Test
    public void testCheckUserKeyPair_Rsa4096_PwEncIsoWithUmlaut_Success()
            throws UnknownVersionException, InvalidKeyPairException, CryptoSystemException {
        testCheckUserKeyPair(
                data("kp_rsa4096_pw_iso_umlaut/private_key.json"),
                data("kp_rsa4096_pw_iso_umlaut/public_key.json"),
                data("kp_rsa4096_pw_iso_umlaut/pw.txt"),
                true);
    }

}
