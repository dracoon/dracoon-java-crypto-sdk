package com.dracoon.sdk.crypto.integration.ruby;

class RubyTestHelper {

    private static final String PATH_BASE = "integration/ruby/";

    private static final String PATH_DATA = PATH_BASE + "data/";
    private static final String PATH_FILES = PATH_BASE + "files/";

    private RubyTestHelper() {

    }

    static String data(String subPath) {
        return PATH_DATA + subPath;
    }

    static String file(String subPath) {
        return PATH_FILES + subPath;
    }

}
