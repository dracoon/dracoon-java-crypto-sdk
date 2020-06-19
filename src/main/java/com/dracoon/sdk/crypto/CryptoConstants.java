package com.dracoon.sdk.crypto;

/**
 * Provides constants for the Dracoon Crypto.
 */
public interface CryptoConstants {

    /**
     * List of available user key pair versions.
     */
    String[] KEY_PAIR_VERSIONS = new String[]{KeyPairVersions.A, KeyPairVersions.RSA4096};

    /**
     * Default user key pair version.
     */
    String DEFAULT_KEY_PAIR_VERSION = KeyPairVersions.A;

    /**
     * Available user key pair versions.
     */
    interface KeyPairVersions {
        String A = "A";
        String RSA4096 = "RSA-4096";
    }

    /**
     * List of available file key versions.
     */
    String[] FILE_KEY_VERSIONS = new String[]{FileKeyVersions.A, FileKeyVersions.RSA4096_AES256GCM};

    /**
     * Default file key version.
     */
    String DEFAULT_FILE_KEY_VERSION = FileKeyVersions.A;

    /**
     * Available file key versions.
     */
    interface FileKeyVersions {
        String A = "A";
        String RSA4096_AES256GCM = "RSA-4096/AES-256-GCM";
    }

}
