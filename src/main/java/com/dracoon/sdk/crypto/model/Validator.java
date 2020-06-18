package com.dracoon.sdk.crypto.model;

public class Validator {

    private Validator() {

    }

    static void validateNotNull(String name, Object object) {
        if (object == null) {
            throw new IllegalArgumentException(name + " cannot be null.");
        }
    }

    static void validateString(String name, String string) {
        validateNotNull(name, string);
        if (string.isEmpty()) {
            throw new IllegalArgumentException(name + " cannot be empty.");
        }
    }

}
