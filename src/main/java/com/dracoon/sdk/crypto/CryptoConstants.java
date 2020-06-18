package com.dracoon.sdk.crypto;

/**
 * Provides constants for the Dracoon Crypto.
 */
public interface CryptoConstants {

    /**
     * Default user key pair version.
     */
    String DEFAULT_KEY_PAIR_VERSION = KeyPairVersions.A;

    /**
     * Available user key pair versions.
     */
    interface KeyPairVersions {
        String A = "A";
    }

    /**
     * Default file key version.
     */
    String DEFAULT_FILE_KEY_VERSION = FileKeyVersions.A;

    /**
     * Available file key versions.
     */
    interface FileKeyVersions {
        String A = "A";
    }

}
