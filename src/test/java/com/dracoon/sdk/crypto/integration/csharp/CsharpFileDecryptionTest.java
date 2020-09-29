package com.dracoon.sdk.crypto.integration.csharp;

public class CsharpFileDecryptionTest extends com.dracoon.sdk.crypto.integration.FileDecryptionTest {

    @Override
    public String data(String subPath) {
        return CsharpTestHelper.data(subPath);
    }

    @Override
    public String file(String subPath) {
        return CsharpTestHelper.file(subPath);
    }

}
