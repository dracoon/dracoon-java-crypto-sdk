package com.dracoon.sdk.crypto.integration.ruby;

public class RubyFileDecryptionTest extends com.dracoon.sdk.crypto.integration.FileDecryptionTest {

    @Override
    public String data(String subPath) {
        return RubyTestHelper.data(subPath);
    }

    @Override
    public String file(String subPath) {
        return RubyTestHelper.file(subPath);
    }

}
