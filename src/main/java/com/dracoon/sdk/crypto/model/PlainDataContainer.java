package com.dracoon.sdk.crypto.model;

/**
 * Holds plain data.
 */
public class PlainDataContainer {

    private final byte[] content;

    /**
     * Constructs a new plain data container.
     *
     * @param content The plain data.
     */
    public PlainDataContainer(byte[] content) {
        this.content = content;
    }

    /**
     * Return the plain data.
     *
     * @return the plain data bytes
     */
    public byte[] getContent() {
        return content;
    }

}
