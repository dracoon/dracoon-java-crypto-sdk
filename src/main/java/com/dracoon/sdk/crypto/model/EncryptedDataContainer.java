package com.dracoon.sdk.crypto.model;

/**
 * Holds encrypted data.
 */
public class EncryptedDataContainer extends DataContainer {

    private final byte[] tag;

    /**
     * Constructs a new encrypted data container.
     *
     * @param content The encrypted data.
     * @param tag     The encryption tag.
     */
    public EncryptedDataContainer(byte[] content, byte[] tag) {
        super(content);
        this.tag = tag;
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
