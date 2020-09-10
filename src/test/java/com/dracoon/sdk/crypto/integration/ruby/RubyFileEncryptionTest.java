package com.dracoon.sdk.crypto.integration.ruby;

public class RubyFileEncryptionTest extends com.dracoon.sdk.crypto.integration.FileEncryptionTest {

    @Override
    public String data(String subPath) {
        return RubyTestHelper.data(subPath);
    }

    @Override
    public String file(String subPath) {
        return RubyTestHelper.file(subPath);
    }

}
