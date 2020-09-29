package com.dracoon.sdk.crypto.model;

/**
 * Holds encrypted data.
 */
public class EncryptedDataContainer {

    private final byte[] content;
    private final byte[] tag;

    /**
     * Constructs a new encrypted data container.
     *
     * @param content The encrypted data.
     * @param tag     The encryption tag.
     */
    public EncryptedDataContainer(byte[] content, byte[] tag) {
        this.content = content;
        this.tag = tag;
    }

    /**
     * Returns the encrypted data.
     *
     * @return the encrypted data bytes
     */
    public byte[] getContent() {
        return content;
    }

    /**
     * Returns the encryption tag
     *
     * @return the encryption tag bytes
     */
    public byte[] getTag() {
        return tag;
    }

}
