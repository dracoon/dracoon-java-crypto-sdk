package com.dracoon.sdk.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import com.dracoon.sdk.crypto.model.EncryptedFileKey;
import com.dracoon.sdk.crypto.model.PlainFileKey;
import com.dracoon.sdk.crypto.model.UserKeyPair;
import com.dracoon.sdk.crypto.model.UserPrivateKey;
import com.dracoon.sdk.crypto.model.UserPublicKey;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.io.pem.PemGenerationException;

/**
 * This class is the main class of the Dracoon Crypto Library.<br>
 * <br>
 * The class provides methods for:<br>
 * - User key pair generation: {@link #generateUserKeyPair(String) generateUserKeyPair}<br>
 * - User key pair check: {@link #checkUserKeyPair(UserKeyPair, String) checkUserKeyPair}<br>
 * - File key generation: {@link #generateFileKey() generateFileKey}<br>
 * - File key encryption: {@link #encryptFileKey(PlainFileKey, UserPublicKey) encryptFileKey}<br>
 * - File key decryption: {@link #decryptFileKey(EncryptedFileKey, UserPrivateKey, String) decryptFileKey}<br>
 * - Cipher creation for file encryption: {@link #createFileEncryptionCipher(PlainFileKey) createFileEncryptionCipher}<br>
 * - Cipher creation for file decryption: {@link #createFileDecryptionCipher(PlainFileKey) createFileDecryptionCipher}<br>
 */
public class Crypto {

    static {
        Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    private static final int HASH_ITERATION_COUNT = 10000;
    private static final int FILE_KEY_SIZE = 32;
    private static final int IV_SIZE = 12;

    private static final String PROP_ALLOW_UNSAFE_INT = "org.bouncycastle.asn1.allow_unsafe_integer";

    private Crypto() {

    }

    // --- KEY MANAGEMENT ---

    /**
     * Generates a random user key pair. (The default encryption version "A" is used.)
     *
     * @param password The password which should be used to secure the private key.
     *
     * @return The generated user key pair.
     *
     * @throws InvalidKeyPairException  If the version for the user key pair is not supported.
     * @throws InvalidPasswordException If the password to secure the private key is invalid.
     * @throws CryptoSystemException    If a unknown error occurred.
     */
    public static UserKeyPair generateUserKeyPair(String password) throws InvalidKeyPairException,
            InvalidPasswordException, CryptoSystemException {
        return generateUserKeyPair(CryptoConstants.DEFAULT_KEY_PAIR_VERSION, password);
    }

    /**
     * Generates a random user key pair.
     *
     * @param version  The encryption version for which the key pair should be created.
     * @param password The password which should be used to secure the private key.
     *
     * @return The generated user key pair.
     *
     * @throws InvalidKeyPairException  If the version for the user key pair is not supported.
     * @throws InvalidPasswordException If the password to secure the private key is invalid.
     * @throws CryptoSystemException    If a unknown error occurred.
     */
    public static UserKeyPair generateUserKeyPair(String version, String password)
            throws InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        validateUserKeyPairVersion(version);
        validatePassword(password);

        KeyPair keyPair;
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            keyPair = keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoSystemException("Could not generate RSA key pair. Algorithm is " +
                    "missing.", e);
        }

        String privateKeyString = encryptPrivateKey(keyPair.getPrivate(), password);
        String publicKeyString = getStringFromPublicKey(keyPair.getPublic());

        UserPrivateKey userPrivateKey = new UserPrivateKey(version, privateKeyString);

        UserPublicKey userPublicKey = new UserPublicKey(version, publicKeyString);

        return new UserKeyPair(userPrivateKey, userPublicKey);
    }

    private static String encryptPrivateKey(PrivateKey privateKey, String password)
            throws InvalidPasswordException, CryptoSystemException {
        OutputEncryptor encryptor;
        try {
            encryptor = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.AES_256_CBC)
                    .setProvider("BC")
                    .setIterationCount(HASH_ITERATION_COUNT)
                    .setPasssword(password.toCharArray())
                    .build();
        } catch (OperatorCreationException e) {
            throw new CryptoSystemException("Could not encrypt private key. Creation of PKCS8" +
                    "(AES 256 CBC) encryptor failed.", e);
        }

        PKCS8Generator generator;
        try {
            generator = new JcaPKCS8Generator(privateKey, encryptor);
        } catch (PemGenerationException e) {
            throw new InvalidPasswordException("Could not encrypt private key. Invalid private " +
                    "key password.", e);
        }

        try {
            StringWriter stringWriter = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
            pemWriter.writeObject(generator);
            pemWriter.close();
            return stringWriter.toString();
        } catch (IOException e) {
            throw new CryptoSystemException("Could not encrypt private key. PEM encoding failed.",
                    e);
        }
    }

    private static PrivateKey decryptPrivateKey(String privateKey, String password)
            throws InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        Object obj;
        try {
            ByteArrayInputStream in = new ByteArrayInputStream(privateKey.getBytes());
            PEMParser pemReader = new PEMParser(new InputStreamReader(in));
            obj = pemReader.readObject();
            pemReader.close();
            in.close();
        } catch (IOException e) {
            throw new InvalidKeyPairException("Could not decrypt private key. PEM decoding failed.",
                    e);
        }

        PrivateKeyInfo pkInfo;
        try {
            if (obj instanceof PKCS8EncryptedPrivateKeyInfo) {
                PKCS8EncryptedPrivateKeyInfo epkInfo = (PKCS8EncryptedPrivateKeyInfo) obj;
                InputDecryptorProvider decryptor = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                        .setProvider("BC")
                        .build(password.toCharArray());
                pkInfo = epkInfo.decryptPrivateKeyInfo(decryptor);
            } else {
                throw new InvalidKeyPairException("Could not decrypt private key. Provided key " +
                        "is not a PKCS8 encrypted private key.");
            }
        } catch (OperatorCreationException e) {
            throw new CryptoSystemException("Could not decrypt private key. Creation of PKCS8 " +
                    "decryptor failed.", e);
        } catch (PKCSException e) {
            throw new InvalidPasswordException("Could not decrypt private key. Invalid private " +
                    "key password.", e);
        }

        try {
            org.bouncycastle.util.Properties.setThreadOverride(PROP_ALLOW_UNSAFE_INT, true);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            return converter.getPrivateKey(pkInfo);
        } catch (PEMException e) {
            throw new CryptoSystemException("Could not decrypted private key. PEM decoding failed.",
                    e);
        } finally {
            org.bouncycastle.util.Properties.removeThreadOverride(PROP_ALLOW_UNSAFE_INT);
        }
    }

    private static String getStringFromPublicKey(PublicKey pubKey) throws InvalidKeyPairException {
        try {
            StringWriter writer = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
            pemWriter.writeObject(pubKey);
            pemWriter.close();
            return writer.toString();
        } catch (IOException e) {
            throw new InvalidKeyPairException("Could not encode public key. PEM encoding failed.",
                    e);
        }
    }

    private static PublicKey getPublicKeyFromString(String pubKey) throws InvalidKeyPairException,
            CryptoSystemException {
        Object obj;
        try {
            ByteArrayInputStream in = new ByteArrayInputStream(pubKey.getBytes());
            PEMParser pemReader = new PEMParser(new InputStreamReader(in));
            obj = pemReader.readObject();
            pemReader.close();
            in.close();
        } catch (IOException e) {
            throw new InvalidKeyPairException("Could not decode public key. PEM decoding failed.",
                    e);
        }

        SubjectPublicKeyInfo pkInfo;
        if (obj instanceof SubjectPublicKeyInfo) {
            pkInfo = (SubjectPublicKeyInfo) obj;
        } else {
            throw new InvalidKeyPairException("Could not decode public key. Provided key is not " +
                    "PKCS8 public key.");
        }

        try {
            org.bouncycastle.util.Properties.setThreadOverride(PROP_ALLOW_UNSAFE_INT, true);
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            return converter.getPublicKey(pkInfo);
        } catch (PEMException e) {
            throw new CryptoSystemException("Could not decode public key. PEM decoding failed.", e);
        } finally {
            org.bouncycastle.util.Properties.removeThreadOverride(PROP_ALLOW_UNSAFE_INT);
        }
    }

    /**
     * Checks if a user key pair can be unlocked.
     *
     * @param userKeyPair The user key pair which should be unlocked.
     * @param password    The password which secures the private key.
     *
     * @return True if the user key pair could be unlocked. Otherwise false.
     *
     * @throws InvalidKeyPairException If the user key pair is invalid.
     * @throws CryptoSystemException   If a unknown error occurred.
     */
    public static boolean checkUserKeyPair(UserKeyPair userKeyPair, String password)
            throws InvalidKeyPairException, CryptoSystemException {
        validateUserKeyPair(userKeyPair);
        validateUserPrivateKey(userKeyPair.getUserPrivateKey());

        if (password == null || password.isEmpty()) {
            return false;
        }

        try {
            decryptPrivateKey(userKeyPair.getUserPrivateKey().getPrivateKey(), password);
            return true;
        } catch(InvalidPasswordException e) {
            return false;
        } catch (InvalidKeyPairException | CryptoSystemException e) {
            throw e;
        }
    }

    // --- ASYMMETRIC ENCRYPTION AND DECRYPTION ---

    /**
     * Encrypts a file key.
     *
     * @param plainFileKey  The file key to encrypt.
     * @param userPublicKey The public key which should be used at the encryption.
     *
     * @return The encrypted file key.
     *
     * @throws InvalidFileKeyException If the provided plain file key is invalid.
     * @throws InvalidKeyPairException If the provided public key is invalid.
     * @throws CryptoSystemException   If a unknown error occurred.
     */
    public static EncryptedFileKey encryptFileKey(PlainFileKey plainFileKey,
            UserPublicKey userPublicKey) throws InvalidFileKeyException, InvalidKeyPairException,
            CryptoSystemException {
        validatePlainFileKey(plainFileKey);
        validateUserPublicKey(userPublicKey);

        PublicKey publicKey = getPublicKeyFromString(userPublicKey.getPublicKey());

        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
            AlgorithmParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1",
                    MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, spec);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidAlgorithmParameterException e) {
            throw new CryptoSystemException("Could not encrypt file key. Creation of cipher " +
                    "failed.", e);
        } catch (InvalidKeyException e) {
            throw new InvalidKeyPairException("Could not encrypt file key. Invalid public key.", e);
        }

        byte[] pFileKey = CryptoUtils.stringToByteArray(plainFileKey.getKey());
        byte[] eFileKey;
        try {
            eFileKey = cipher.doFinal(pFileKey);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new CryptoSystemException("Could not encrypt file key. Encryption failed.", e);
        }

        EncryptedFileKey encFileKey = new EncryptedFileKey(plainFileKey.getVersion(), CryptoUtils
                .byteArrayToString(eFileKey), plainFileKey.getIv());

        encFileKey.setTag(plainFileKey.getTag());

        return encFileKey;
    }

    /**
     * Decrypts a file key.
     *
     * @param encFileKey     The file key to decrypt.
     * @param userPrivateKey The private key which should be used at the decryption.
     * @param password       The password which secures the private key.
     *
     * @return The decrypted file key.
     *
     * @throws InvalidFileKeyException  If the provided encrypted file key is invalid.
     * @throws InvalidKeyPairException  If the provided private key is invalid.
     * @throws InvalidPasswordException If the provided private key password is invalid.
     * @throws CryptoSystemException    If a unknown error occurred.
     */
    public static PlainFileKey decryptFileKey(EncryptedFileKey encFileKey,
            UserPrivateKey userPrivateKey, String password) throws InvalidFileKeyException,
            InvalidKeyPairException, InvalidPasswordException, CryptoSystemException {
        validateEncryptedFileKey(encFileKey);
        validateUserPrivateKey(userPrivateKey);
        validatePassword(password);

        PrivateKey privateKey = decryptPrivateKey(userPrivateKey.getPrivateKey(), password);

        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
            AlgorithmParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1",
                    MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
            cipher.init(Cipher.DECRYPT_MODE, privateKey, spec);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidAlgorithmParameterException e) {
            throw new CryptoSystemException("Could not decrypt file key. Creation of cipher " +
                    "failed.", e);
        } catch (InvalidKeyException e) {
            throw new InvalidKeyPairException("Could not decrypt file key. Invalid private key.", e);
        }

        byte[] eFileKey = CryptoUtils.stringToByteArray(encFileKey.getKey());
        byte[] dFileKey;
        try {
            dFileKey = cipher.doFinal(eFileKey);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new InvalidFileKeyException("Could not decrypt file key. Encryption failed.", e);
        }

        PlainFileKey plainFileKey = new PlainFileKey(encFileKey.getVersion(), CryptoUtils.
                byteArrayToString(dFileKey), encFileKey.getIv());

        plainFileKey.setTag(encFileKey.getTag());

        return plainFileKey;
    }

    // --- SYMMETRIC ENCRYPTION AND DECRYPTION ---

    /**
     * Generates a random file key. (The default encryption version "A" is used.)
     *
     * @return The generated file key.
     */
    public static PlainFileKey generateFileKey() {
        try {
            return generateFileKey(CryptoConstants.DEFAULT_FILE_KEY_VERSION);
        } catch (InvalidFileKeyException e) {
            // Nothing to do here
            return null;
        }
    }

    /**
     * Generates a random file key.
     *
     * @param version The encryption version for which the file key should be created.
     *
     * @return The generated file key.
     *
     * @throws InvalidFileKeyException If the version for the file key is not supported.
     */
    public static PlainFileKey generateFileKey(String version) throws InvalidFileKeyException {
        validateFileKeyVersion(version);

        byte[] key = generateSecureRandomByteArray(FILE_KEY_SIZE);
        byte[] iv = generateSecureRandomByteArray(IV_SIZE);

        return new PlainFileKey(version, CryptoUtils.byteArrayToString(key), CryptoUtils
                .byteArrayToString(iv));
    }

    private static byte[] generateSecureRandomByteArray(int size) {
        SecureRandom sr = new SecureRandom();
        byte[] bytes = new byte[size];
        sr.nextBytes(bytes);
        return bytes;
    }

    /**
     * Creates a file encryption cipher.
     *
     * @param fileKey The file key which should be used at the encryption.
     *
     * @return The file encryption cipher.
     *
     * @throws InvalidFileKeyException If the provided file key is invalid.
     * @throws CryptoSystemException   If a unknown error occurred.
     */
    public static FileEncryptionCipher createFileEncryptionCipher(PlainFileKey fileKey)
            throws InvalidFileKeyException, CryptoSystemException {
        validatePlainFileKey(fileKey);
        return new FileEncryptionCipher(fileKey);
    }

    /**
     * Creates a file decryption cipher.
     *
     * @param fileKey The file key which should be used at the decryption.
     *
     * @return The file decryption cipher.
     *
     * @throws InvalidFileKeyException If the provided file key is invalid.
     * @throws CryptoSystemException   If a unknown error occurred.
     */
    public static FileDecryptionCipher createFileDecryptionCipher(PlainFileKey fileKey)
            throws InvalidFileKeyException, CryptoSystemException {
        validatePlainFileKey(fileKey);
        return new FileDecryptionCipher(fileKey);
    }

    // --- VALIDATORS ---

    private static void validatePassword(String password) throws InvalidPasswordException {
        if (password == null || password.isEmpty()) {
            throw new InvalidPasswordException("Password cannot be null or empty.");
        }
    }

    private static void validateUserKeyPair(UserKeyPair userKeyPair)
            throws InvalidKeyPairException {
        if (userKeyPair == null) {
            throw new InvalidKeyPairException("User key pair cannot be null.");
        }
    }

    private static void validateUserKeyPairVersion(String version) throws InvalidKeyPairException {
        if (version == null || version.isEmpty() ||
                !version.equals(CryptoConstants.DEFAULT_KEY_PAIR_VERSION)) {
            throw new InvalidKeyPairException("Unknown user key pair version.");
        }
    }

    private static void validateUserPrivateKey(UserPrivateKey privateKey)
            throws InvalidKeyPairException {
        if (privateKey == null) {
            throw new InvalidKeyPairException("Private key container cannot be null.");
        }
        String version = privateKey.getVersion();
        if (!version.equals(CryptoConstants.DEFAULT_KEY_PAIR_VERSION)) {
            throw new InvalidKeyPairException("Unknown private key version.");
        }
    }

    private static void validateUserPublicKey(UserPublicKey publicKey)
            throws InvalidKeyPairException {
        if (publicKey == null) {
            throw new InvalidKeyPairException("Public key container cannot be null.");
        }
        String version = publicKey.getVersion();
        if (!version.equals(CryptoConstants.DEFAULT_KEY_PAIR_VERSION)) {
            throw new InvalidKeyPairException("Unknown public key version.");
        }
    }

    private static void validateFileKeyVersion(String version) throws InvalidFileKeyException {
        if (version == null || version.isEmpty()) {
            throw new InvalidFileKeyException("Unknown file key version.");
        }
    }

    private static void validatePlainFileKey(PlainFileKey fileKey) throws InvalidFileKeyException {
        if (fileKey == null) {
            throw new InvalidFileKeyException("File key cannot be null.");
        }
        String version = fileKey.getVersion();
        if (!version.equals(CryptoConstants.DEFAULT_FILE_KEY_VERSION)) {
            throw new InvalidFileKeyException("Unknown file key version.");
        }
    }

    private static void validateEncryptedFileKey(EncryptedFileKey fileKey)
            throws InvalidFileKeyException {
        if (fileKey == null) {
            throw new InvalidFileKeyException("File key cannot be null.");
        }
        String version = fileKey.getVersion();
        if (!version.equals(CryptoConstants.DEFAULT_FILE_KEY_VERSION)) {
            throw new InvalidFileKeyException("Unknown file key version.");
        }
    }

}
