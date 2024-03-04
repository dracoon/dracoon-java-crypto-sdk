package com.dracoon.sdk.crypto.model;

import com.dracoon.sdk.crypto.internal.Validator;

public abstract class FileKey<T> {

    private final T version;
    private final byte[] key;
    private final byte[] iv;

    private byte[] tag;

    protected FileKey(T version, byte[] key, byte[] iv) throws IllegalArgumentException {
        Validator.validateNotNull("version", version);
        Validator.validateByteArray("key", key);
        Validator.validateByteArray("iv", iv);
        this.version = version;
        this.key = key;
        this.iv = iv;
    }

    /**
     * Returns the file key version.
     *
     * @return the version
     */
    public T getVersion() {
        return version;
    }

    /**
     * Returns the file key.
     *
     * @return the file key
     */
    public byte[] getKey() {
        return key;
    }

    /**
     * Returns the encryption initialization vector.
     *
     * @return the initialization vector
     */
    public byte[] getIv() {
        return iv;
    }

    /**
     * Returns the encryption tag.
     *
     * @return the tag
     */
    public byte[] getTag() {
        return tag;
    }

    /**
     * Set the encryption tag.
     *
     * @param tag The encryption tag.
     */
    public void setTag(byte[] tag) {
        this.tag = tag;
    }

}
