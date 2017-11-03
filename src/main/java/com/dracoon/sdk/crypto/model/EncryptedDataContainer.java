package com.dracoon.sdk.crypto.model;

public class EncryptedDataContainer {

    private byte[] content;
    private byte[] tag;

    public EncryptedDataContainer(byte[] content, byte[] tag) {
        this.content = content;
        this.tag = tag;
    }

    public byte[] getContent() {
        return content;
    }

    public byte[] getTag() {
        return tag;
    }

}
