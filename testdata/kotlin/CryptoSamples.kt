package com.example.demo

import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.util.Arrays
import java.util.Random

// Sample for cryptobom regression testing. Kotlin uses the same JCA APIs as Java.
class CryptoSamples {

    fun vulnerable() {
        // Quantum-vulnerable asymmetric crypto.
        val rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        val sig = Signature.getInstance("SHA1withRSA")
        val ka = KeyAgreement.getInstance("ECDH")
    }

    fun weakAndMisused() {
        // Weak / deprecated algorithms and a classic misuse.
        val des = Cipher.getInstance("DES")
        val aesEcb = Cipher.getInstance("AES/ECB/PKCS5Padding")
        val md5 = MessageDigest.getInstance("MD5")
        // Deprecated TLS protocol version (SSLContext is JVM, shared with Java).
        val legacy = javax.net.ssl.SSLContext.getInstance("SSLv3")
    }

    fun enabledProtocols(socket: javax.net.ssl.SSLSocket) {
        // Enabled-protocols set on the socket — TLSv1 flagged, TLSv1.2 inventory.
        socket.setEnabledProtocols(arrayOf("TLSv1", "TLSv1.2"))
    }

    fun keySizesAndMisuse(iv: ByteArray) {
        // Key size linked from a later initialize() call (dataflow).
        val weakRsa = KeyPairGenerator.getInstance("RSA")
        weakRsa.initialize(1024)
        val strongRsa = KeyPairGenerator.getInstance("RSA")
        strongRsa.initialize(3072)

        // Hardcoded key and static IV.
        val key = SecretKeySpec("hardcoded-demo-key".toByteArray(), "AES")
        val staticIv = IvParameterSpec("0123456789abcdef".toByteArray())
        // Variable IV — must NOT be flagged.
        val dynamicIv = IvParameterSpec(iv)

        // Key material from a non-cryptographic PRNG — flagged via sink taint.
        val buf = ByteArray(16)
        val rng = Random()
        rng.nextBytes(buf)
        val fromWeak = SecretKeySpec(buf, "AES")

        // SecureRandom is correct — must NOT be flagged.
        val good = ByteArray(16)
        val sr = SecureRandom()
        sr.nextBytes(good)
        val fromSecure = SecretKeySpec(good, "AES")
    }

    fun timingCompare(key: ByteArray, msg: ByteArray, provided: ByteArray): Boolean {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        val tag = mac.doFinal(msg)
        // Non-constant-time comparison of a MAC — flagged.
        if (Arrays.equals(tag, provided)) {
            return true
        }
        // Constant-time comparison — must NOT be flagged.
        if (MessageDigest.isEqual(tag, provided)) {
            return true
        }
        // Non-crypto comparison — must NOT be flagged.
        return msg.contentEquals(provided)
    }

    fun postQuantum() {
        // Post-quantum algorithm — inventoried as quantum-safe.
        val mldsa = KeyPairGenerator.getInstance("ML-DSA")
    }

    fun strongOrInventory() {
        // Good usage — must NOT be flagged as a problem.
        val aesGcm = Cipher.getInstance("AES/GCM/NoPadding")
        val sha256 = MessageDigest.getInstance("SHA-256")
    }

    fun unanalyzable(algName: String) {
        // Non-literal argument — cannot be resolved safely, must be ignored.
        val dynamic = Cipher.getInstance(algName)
    }
}
