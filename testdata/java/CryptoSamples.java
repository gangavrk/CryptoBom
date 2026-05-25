package com.example.demo;

import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Random;

// Sample for cryptobom regression testing. Mixes vulnerable, weak, misused,
// strong, and unanalyzable (non-literal) cryptographic usage.
public class CryptoSamples {

    void vulnerable() throws Exception {
        // Quantum-vulnerable asymmetric crypto. OAEP padding is the safe form;
        // PKCS#1 v1.5 encryption padding (below) is Bleichenbacher-vulnerable.
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        Cipher rsaLegacy = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        KeyPairGenerator rsaKeys = KeyPairGenerator.getInstance("RSA");
        KeyPairGenerator ecKeys = KeyPairGenerator.getInstance("EC");
        Signature sig = Signature.getInstance("SHA1withRSA");
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
    }

    void weakAndMisused() throws Exception {
        // Weak / deprecated algorithms and a classic misuse.
        Cipher des = Cipher.getInstance("DES");
        Cipher aesEcb = Cipher.getInstance("AES/ECB/PKCS5Padding");
        // No mode specified → the JCE silently defaults to ECB.
        Cipher aesNoMode = Cipher.getInstance("AES");
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        // MAC over a broken hash (HMAC-SHA256 in timingCompare() is the safe form).
        Mac weakMac = Mac.getInstance("HmacMD5");
        // Deprecated TLS protocol version; the modern one is inventory-only.
        javax.net.ssl.SSLContext legacy = javax.net.ssl.SSLContext.getInstance("TLSv1.1");
        javax.net.ssl.SSLContext modern = javax.net.ssl.SSLContext.getInstance("TLSv1.3");
    }

    void enabledProtocols(javax.net.ssl.SSLSocket socket) {
        // Enabled-protocols set on the socket — TLSv1 flagged, TLSv1.2 inventory.
        socket.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.2"});
    }

    void hardcoded(byte[] iv) throws Exception {
        // Hardcoded key and static IV — literal material in source.
        SecretKeySpec key = new SecretKeySpec("hardcoded-demo-key".getBytes(), "AES");
        IvParameterSpec staticIv = new IvParameterSpec("0123456789abcdef".getBytes());
        // Variable IV — must NOT be flagged.
        IvParameterSpec dynamicIv = new IvParameterSpec(iv);
    }

    void keySizesAndPrng() throws Exception {
        // Key size linked from a later initialize() call (intra-procedural dataflow).
        KeyPairGenerator weakRsa = KeyPairGenerator.getInstance("RSA");
        weakRsa.initialize(1024);
        KeyPairGenerator strongRsa = KeyPairGenerator.getInstance("RSA");
        strongRsa.initialize(3072);

        // Key material from a non-cryptographic PRNG — flagged via sink taint.
        byte[] weakKey = new byte[16];
        Random rng = new Random();
        rng.nextBytes(weakKey);
        SecretKeySpec fromWeak = new SecretKeySpec(weakKey, "AES");

        // SecureRandom is correct — must NOT be flagged.
        byte[] goodKey = new byte[16];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(goodKey);
        SecretKeySpec fromSecure = new SecretKeySpec(goodKey, "AES");
    }

    boolean timingCompare(byte[] key, byte[] msg, byte[] provided) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        byte[] tag = mac.doFinal(msg);
        // Non-constant-time comparison of a MAC — flagged.
        if (Arrays.equals(tag, provided)) {
            return true;
        }
        // Constant-time comparison — must NOT be flagged.
        if (MessageDigest.isEqual(tag, provided)) {
            return true;
        }
        // Non-crypto comparison — must NOT be flagged.
        return Arrays.equals(msg, provided);
    }

    void strongOrInventory() throws Exception {
        // Good usage — must NOT be flagged as a problem.
        Cipher aesGcm = Cipher.getInstance("AES/GCM/NoPadding");
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        KeyGenerator aesKey = KeyGenerator.getInstance("AES");
    }

    void postQuantum() throws Exception {
        // Post-quantum algorithms (BouncyCastle) — inventoried as quantum-safe.
        KeyPairGenerator mlkem = KeyPairGenerator.getInstance("ML-KEM");
        KeyPairGenerator mldsa = KeyPairGenerator.getInstance("Dilithium");
    }

    void unanalyzable(String algName) throws Exception {
        // Non-literal argument — cannot be resolved safely, must be ignored.
        Cipher dynamic = Cipher.getInstance(algName);
    }
}
