package com.dracoon.sdk.crypto.integration.js;

public class JsFileDecryptionTest extends com.dracoon.sdk.crypto.integration.FileDecryptionTest {

    @Override
    public String data(String subPath) {
        return JsTestHelper.data(subPath);
    }

    @Override
    public String file(String subPath) {
        return JsTestHelper.file(subPath);
    }

}
