package com.example.demo;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;

// Sample for cryptobom regression testing. Mixes vulnerable, weak, misused,
// strong, and unanalyzable (non-literal) cryptographic usage.
public class CryptoSamples {

    void vulnerable() throws Exception {
        // Quantum-vulnerable asymmetric crypto.
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        KeyPairGenerator rsaKeys = KeyPairGenerator.getInstance("RSA");
        KeyPairGenerator ecKeys = KeyPairGenerator.getInstance("EC");
        Signature sig = Signature.getInstance("SHA1withRSA");
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    }

    void weakAndMisused() throws Exception {
        // Weak / deprecated algorithms and a classic misuse.
        Cipher des = Cipher.getInstance("DES");
        Cipher aesEcb = Cipher.getInstance("AES/ECB/PKCS5Padding");
        MessageDigest md5 = MessageDigest.getInstance("MD5");
    }

    void hardcoded(byte[] iv) throws Exception {
        // Hardcoded key and static IV — literal material in source.
        SecretKeySpec key = new SecretKeySpec("hardcoded-demo-key".getBytes(), "AES");
        IvParameterSpec staticIv = new IvParameterSpec("0123456789abcdef".getBytes());
        // Variable IV — must NOT be flagged.
        IvParameterSpec dynamicIv = new IvParameterSpec(iv);
    }

    void strongOrInventory() throws Exception {
        // Good usage — must NOT be flagged as a problem.
        Cipher aesGcm = Cipher.getInstance("AES/GCM/NoPadding");
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        KeyGenerator aesKey = KeyGenerator.getInstance("AES");
    }

    void unanalyzable(String algName) throws Exception {
        // Non-literal argument — cannot be resolved safely, must be ignored.
        Cipher dynamic = Cipher.getInstance(algName);
    }
}
