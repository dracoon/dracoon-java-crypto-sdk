package com.dracoon.sdk.crypto.model;

public class UserKeyPair {

    private UserPrivateKey userPrivateKey;
    private UserPublicKey userPublicKey;

    public UserPrivateKey getUserPrivateKey() {
        return userPrivateKey;
    }

    public void setUserPrivateKey(UserPrivateKey userPrivateKey) {
        this.userPrivateKey = userPrivateKey;
    }

    public UserPublicKey getUserPublicKey() {
        return userPublicKey;
    }

    public void setUserPublicKey(UserPublicKey userPublicKey) {
        this.userPublicKey = userPublicKey;
    }

}
