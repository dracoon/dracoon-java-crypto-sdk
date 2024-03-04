package com.dracoon.sdk.crypto.model;

public abstract class DataContainer {

    private final byte[] content;

    protected DataContainer(byte[] content) {
        this.content = content;
    }

    /**
     * Returns the data.
     *
     * @return the data bytes
     */
    public byte[] getContent() {
        return content;
    }

}
