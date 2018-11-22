[![Build Status](https://travis-ci.org/dracoon/dracoon-java-crypto-sdk.svg?branch=master)](https://travis-ci.org/dracoon/)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.dracoon/dracoon-crypto-sdk/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.dracoon/dracoon-crypto-sdk)
# Dracoon Java Crypto SDK

A library which implements the client-side encryption of Dracoon.

# Introduction

Later, a link to the Dracoon client-side encryption white paper will be added here. This document
will describe the client-side encryption in detail. 

# Setup

#### Minimum Requirements

Java 6 or newer

#### Download

Maven: Add this dependency to your pom.xml:
```xml
<dependency>
    <groupId>com.dracoon</groupId>
    <artifactId>dracoon-crypto-sdk</artifactId>
    <version>1.0.0</version>
</dependency>
```

Gradle: Add this dependency to your build.gradle:
```groovy
compile 'com.dracoon:dracoon-crypto-sdk:1.0.0'
```

JAR import: The latest JAR can be found [here](https://github.com/dracoon/sdk-crypto-java/releases).

Note that you also need to include the following dependencies:
1. Bouncy Castle Provider: https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk15on
2. Bouncy Castle PKIX/CMS/...: https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk15on

#### Java JCE Setup

**IMPORTANT FOR JAVA VERSIONS 6 (<191), 7 (<181) and 8 (<162):**

You need to install the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy
Files. Otherwise you'll get an exception about key length or an exception when parsing PKCS private
keys.

The Unlimited Strength Jurisdiction Policy File can be found here:
- Java 6: https://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html
- Java 7: https://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html
- Java 8: https://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html

(For more information see: https://stackoverflow.com/questions/1179672)

# Example

An example can be found here: `example/src/main/java/com/dracoon/sdk/crypto/example/Main.java`

The example shows the complete encryption workflow, i.e. generate user keypair, validate user
keypair, generate file key, encrypt file key, and finally encrypt and decrypt a file.

```java
public static void main(String[] args) throws Exception {
    // --- INITIALIZATION ---
    // Generate key pair
    UserKeyPair userKeyPair = Crypto.generateUserKeyPair(USER_PASSWORD);
    // Check key pair
    if (!Crypto.checkUserKeyPair(userKeyPair, USER_PASSWORD)) {
        ...
    }

    byte[] plainData = DATA.getBytes("UTF8");

    ...

    // --- ENCRYPTION ---
    // Generate plain file key
    PlainFileKey fileKey = Crypto.generateFileKey();
    // Encrypt blocks
    byte[] encData = encryptData(fileKey, plainData);
    // Encrypt file key
    EncryptedFileKey encFileKey = Crypto.encryptFileKey(fileKey, userKeyPair.getUserPublicKey());

    ...

    // --- DECRYPTION ---
    // Decrypt file key
    PlainFileKey decFileKey = Crypto.decryptFileKey(encFileKey, userKeyPair.getUserPrivateKey(),
            USER_PASSWORD);
    // Decrypt blocks
    byte[] decData = decryptData(decFileKey, encData);

    ...
}
```

# Copyright and License

Copyright 2017 Dracoon GmbH. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.