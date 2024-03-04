package com.dracoon.sdk.crypto.internal;

import java.util.Objects;

public class Validator {

    private Validator() {

    }

    public static void validateNotNull(String name, Object object) {
        if (object == null) {
            throw new IllegalArgumentException(String.format("'%s' cannot be null.", name));
        }
    }

    public static void validateCharArray(String name, char[] chars) {
        validateNotNull(name, chars);
        if (chars.length == 0) {
            throw new IllegalArgumentException(String.format("'%s' cannot be empty.", name));
        }
    }

    public static void validateByteArray(String name, byte[] bytes) {
        validateNotNull(name, bytes);
        if (bytes.length == 0) {
            throw new IllegalArgumentException(String.format("'%s' cannot be empty.", name));
        }
    }

    public static <T> void validateEqual(String name1, T value1, String name2, T value2) {
        if (!Objects.equals(value1, value2)) {
            throw new IllegalArgumentException(String.format("'%s' and '%s' must be equal.", name1,
                    name2));
        }
    }

}
