package com.dracoon.sdk.crypto.integration.csharp;

class CsharpTestHelper {

    private static final String PATH_BASE = "integration/csharp/";

    private static final String PATH_DATA = PATH_BASE + "data/";
    private static final String PATH_FILES = PATH_BASE + "files/";

    private CsharpTestHelper() {

    }

    static String data(String subPath) {
        return PATH_DATA + subPath;
    }

    static String file(String subPath) {
        return PATH_FILES + subPath;
    }

}
