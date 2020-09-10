package com.dracoon.sdk.crypto.integration.ruby;

import com.dracoon.sdk.crypto.model.UserKeyPair;

public class RubyCryptoTest extends com.dracoon.sdk.crypto.integration.CryptoTest {

    @Override
    public String password(UserKeyPair.Version version) {
        return "Qwer1234!";
    }

    @Override
    public String data(String subPath) {
        return RubyTestHelper.data(subPath);
    }

    @Override
    public String file(String subPath) {
        return RubyTestHelper.file(subPath);
    }

}
