package com.example.encryption;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.util.Date;
import java.util.Properties;

public class PGPKeyPairGenerator {
    private static String rsaAlgorithm;
    private static int rsaKeySize;
    private static String aesAlgorithm;
    private static int aesKeySize;
    private static String password;
    private static Date keyExpirationDate;

    static {
        Security.addProvider(new BouncyCastleProvider());
        loadConfig();
    }

    public static void main(String[] args) {
        try {
            PGPKeyPair pgpKeyPair = generatePGPKeyPair();
            SecretKey aesKey = generateAESKey();

            // Export the PGP keys
            String publicKey = exportPublicKey(pgpKeyPair.getPublicKey());
            String privateKey = exportPrivateKey(pgpKeyPair);

            // Save keys to files in the "keys" directory
            saveKeyToFile("keys/publicKey.asc", publicKey);
            saveKeyToFile("keys/privateKey.asc", privateKey);

            // Export AES key if needed
            String aesKeyString = exportAESKey(aesKey);
            saveKeyToFile("keys/aesKey.txt", aesKeyString);

            System.out.println("Keys have been generated and saved successfully.");
        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void loadConfig() {
        Properties properties = new Properties();
        try (InputStream input = PGPKeyPairGenerator.class.getClassLoader().getResourceAsStream("encryption-config.properties")) {
            if (input == null) {
                System.out.println("Sorry, unable to find encryption-config.properties");
                return;
            }
            properties.load(input);

            rsaAlgorithm = properties.getProperty("rsa.algorithm", "RSA");
            rsaKeySize = Integer.parseInt(properties.getProperty("rsa.keysize", "2048"));
            aesAlgorithm = properties.getProperty("aes.algorithm", "AES");
            aesKeySize = Integer.parseInt(properties.getProperty("aes.keysize", "256"));
            password = properties.getProperty("encryption.password", "mySecretPassword");
            String expirationDateStr = properties.getProperty("key.expiration.date", "2025-12-31"); // default expiration date
            keyExpirationDate = java.sql.Date.valueOf(expirationDateStr);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static PGPKeyPair generatePGPKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(rsaAlgorithm, "BC");
        kpg.initialize(rsaKeySize);
        KeyPair kp = kpg.generateKeyPair();

        // Create PGP key pair
        PGPKeyPair pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, kp, new Date());

        // Note: Key expiration is not directly supported in this way with Bouncy Castle.
        // You can manage expiration manually or use other mechanisms.

        return pgpKeyPair;
    }

    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(aesAlgorithm);
        keyGen.init(aesKeySize);
        return keyGen.generateKey();
    }

    public static String exportPublicKey(PGPPublicKey publicKey) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armoredOut = new ArmoredOutputStream(out);
        publicKey.encode(armoredOut);
        armoredOut.close();
        return out.toString();
    }

    public static String exportPrivateKey(PGPKeyPair keyPair) throws Exception {
        PGPSecretKey secretKey = new PGPSecretKey(
                PGPSignature.DEFAULT_CERTIFICATION,
                keyPair,
                "test@example.com",
                null,
                null,
                null,
                new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), PGPUtil.SHA256),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA256))
                        .build(password.toCharArray())
        );

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ArmoredOutputStream armoredOut = new ArmoredOutputStream(out);
        secretKey.encode(armoredOut);
        armoredOut.close();
        return out.toString();
    }

    public static String exportAESKey(SecretKey aesKey) {
        return bytesToHex(aesKey.getEncoded());
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static void saveKeyToFile(String filename, String key) throws Exception {
        File file = new File(filename);
        file.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(key.getBytes());
        }
    }
}
