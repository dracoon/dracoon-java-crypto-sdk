package com.dracoon.sdk.crypto.integration.js;

class JsTestHelper {

    private static final String PATH_BASE = "integration/js/";

    private static final String PATH_DATA = PATH_BASE + "data/";
    private static final String PATH_FILES = PATH_BASE + "files/";

    private JsTestHelper() {

    }

    static String data(String subPath) {
        return PATH_DATA + subPath;
    }

    static String file(String subPath) {
        return PATH_FILES + subPath;
    }

}
