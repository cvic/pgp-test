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
import java.io.OutputStream;
import java.security.*;
import java.util.Date;

public class PGPKeyPairGenerator {
    static {
        Security.addProvider(new BouncyCastleProvider());
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

            // Optionally, export AES key if needed
            String aesKeyString = exportAESKey(aesKey);
            saveKeyToFile("keys/aesKey.txt", aesKeyString);

            System.out.println("Keys have been generated and saved successfully.");
        } catch (Exception e) {
            System.err.println("An error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static PGPKeyPair generatePGPKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        return new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, kp, new Date());
    }

    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // AES-256
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
                        .build("password".toCharArray())
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
        file.getParentFile().mkdirs(); // Create directories if they do not exist
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(key.getBytes());
        }
    }
}
