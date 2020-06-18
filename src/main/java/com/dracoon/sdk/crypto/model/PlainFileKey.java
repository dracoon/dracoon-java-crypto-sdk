package com.dracoon.sdk.crypto.model;

/**
 * Plain file key model.<br>
 * <br>
 * This model holds plain file key data.
 */
public class PlainFileKey {

    private final String version;
    private final String key;
    private final String iv;

    private String tag;

    /**
     * Constructs a new plain file key.
     *
     * @param version The file key version.
     * @param key     The plain Base64 encoded file key.
     * @param iv      The encryption initialization vector.
     */
    public PlainFileKey(String version, String key, String iv) {
        Validator.validateString("version", version);
        Validator.validateString("key", key);
        Validator.validateString("iv", iv);
        this.version = version;
        this.key = key;
        this.iv = iv;
    }

    /**
     * Returns the plain file key version.
     *
     * @return the version
     */
    public String getVersion() {
        return version;
    }

    /**
     * Returns the plain Base64 encoded file key.
     *
     * @return the file key
     */
    public String getKey() {
        return key;
    }

    /**
     * Returns the encryption initialization vector.
     *
     * @return the initialization vector
     */
    public String getIv() {
        return iv;
    }

    /**
     * Returns the encryption tag.
     *
     * @return the tag
     */
    public String getTag() {
        return tag;
    }

    /**
     * Set the encryption tag.
     *
     * @param tag The encryption tag.
     */
    public void setTag(String tag) {
        this.tag = tag;
    }

}
