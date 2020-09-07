package com.dracoon.sdk.crypto;

class TestHelper {

    private static final String PATH_BASE = "";

    private static final String PATH_DATA = PATH_BASE + "data/";
    private static final String PATH_FILES = PATH_BASE + "files/";

    private TestHelper() {

    }

    static String data(String subPath) {
        return PATH_DATA + subPath;
    }

    static String file(String subPath) {
        return PATH_FILES + subPath;
    }

}
