[![Build](https://github.com/dracoon/dracoon-java-crypto-sdk/actions/workflows/build.yml/badge.svg)](https://github.com/dracoon/dracoon-java-crypto-sdk/actions/workflows/build.yml)
[![Unit Tests](https://github.com/dracoon/dracoon-java-crypto-sdk/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/dracoon/dracoon-java-crypto-sdk/actions/workflows/unit-tests.yml)
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.dracoon/dracoon-crypto-sdk/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.dracoon/dracoon-crypto-sdk)
# Dracoon Java Crypto SDK

A library which implements the client-side encryption of Dracoon.

# Introduction

A document which describes the client-side encryption in detail can be found here:

https://support.dracoon.com/hc/en-us/articles/360000986345 

# Setup

#### Minimum Requirements

Java 8 or newer

#### Download

Maven: Add this dependency to your pom.xml:
```xml
<dependency>
    <groupId>com.dracoon</groupId>
    <artifactId>dracoon-crypto-sdk</artifactId>
    <version>3.0.2</version>
</dependency>
```

Gradle: Add this dependency to your build.gradle:
```groovy
compile 'com.dracoon:dracoon-crypto-sdk:3.0.2'
```

JAR import: The latest JAR can be found [here](
https://github.com/dracoon/dracoon-java-crypto-sdk/releases).

Note that you also need to include the following dependencies:
1. Bouncy Castle PKIX/CMS/...: https://mvnrepository.com/artifact/org.bouncycastle/bcpkix-jdk18on:1.80
2. Bouncy Castle Provider: https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk18on:1.80
3. Bouncy Castle Utils: https://mvnrepository.com/artifact/org.bouncycastle/bcutil-jdk18on:1.80

#### Java JCE Setup

**IMPORTANT FOR JAVA VERSION 8 (<162):**

You need to install the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy
Files. Otherwise you'll get an exception about key length or an exception when parsing PKCS private
keys.

The Unlimited Strength Jurisdiction Policy File can be found here:
- Java 8: https://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html

For Java 9 and above, the Unlimited Strength Jurisdiction Policy Files are no longer needed.
(For more information see: https://stackoverflow.com/questions/1179672)

#### Usage on Android

The Android platform ships with a cut-down version of Bouncy Castle. In the past (pre-Android 3.0),
this caused conflicts and there was a separate version of the Crypto SDK for Android which used
Spongy Castle.

Because there are very few people who use pre-Android 3.0 devices, and the fact that Spongy Castle
is not maintained anymore, there is no longer a separate version.

To avoid problems you should reinitialize the Bouncy Castle security provider when your application
starts. This can be done by extending `Application` and using a static initialization block. See
following example.

```java
...

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DracoonApplication extends Application {
    
    static {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(new BouncyCastleProvider());
    }

    ...
    
}
```

# Example

An example can be found here: `example/src/main/java/com/dracoon/sdk/crypto/example/Main.java`

The example shows the complete encryption workflow, i.e. generate user keypair, validate user
keypair, generate file key, encrypt file key, and finally encrypt and decrypt a file.

```java
public static void main(String[] args) throws Exception {
    // --- INITIALIZATION ---
    // Generate key pair
    UserKeyPair userKeyPair = Crypto.generateUserKeyPair(UserKeyPair.Version.RSA2048,
            USER_PASSWORD);
    // Check key pair
    if (!Crypto.checkUserKeyPair(userKeyPair, USER_PASSWORD)) {
        ...
    }

    byte[] plainData = DATA.getBytes("UTF8");

    ...

    // --- ENCRYPTION ---
    // Generate plain file key
    PlainFileKey fileKey = Crypto.generateFileKey(PlainFileKey.Version.AES256GCM);
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

## Contribution

If you would like to contribute code, fork the repository and send a pull request. When submitting
code, please make every effort to follow existing conventions and style in order to keep the code as
readable as possible.

# Copyright and License

Copyright Dracoon GmbH. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.