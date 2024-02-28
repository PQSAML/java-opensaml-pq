/*
 * Licensed to the University Corporation for Advanced Internet Development,
 * Inc. (UCAID) under one or more contributor license agreements.  See the
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache
 * License, Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opensaml.security.crypto;

import java.security.Key;

/**
 * Various useful constants defined in and/or used with the Java Cryptography Architecture (JCA) specification.
 */
public final class JCAConstants {

    // Key types

    /** Key algorithm: "RSA". */
    public static final String KEY_ALGO_RSA = "RSA";

    /** Key algorithm: "DSA". */
    public static final String KEY_ALGO_DSA = "DSA";

    /** Key algorithm: "EC". */
    public static final String KEY_ALGO_EC = "EC";

    /** Key algorithm: "AES". */
    public static final String KEY_ALGO_AES = "AES";

    /** Key algorithm: "DES". */
    public static final String KEY_ALGO_DES = "DES";

    /** Key algorithm: "DESede". */
    public static final String KEY_ALGO_DESEDE = "DESede";

    /** Key algorithm: "DH" (returned by {@link Key#getAlgorithm()}). */
    public static final String KEY_ALGO_DH = "DH";

    /** Key algorithm: "DiffieHellman" (used with key and key pair factories, generators, etc). */
    public static final String KEY_ALGO_DIFFIE_HELLMAN = "DiffieHellman";

    public static final String KEY_ALGO_DILITHIUM = "Dilithium";
    public static final String KEY_ALGO_FALCON = "Falcon";
    public static final String KEY_ALGO_CMCE = "CMCE";
    public static final String KEY_ALGO_KYBER = "KYBER";
    public static final String KEY_ALGO_BIKE = "BIKE";
    public static final String KEY_ALGO_HQC = "HQC";
    public static final String KEY_ALGO_SPHINCSPLUS = "SPHINCSPlus";
    public static final String KEY_ALGO_MLDSA44andECDSAP256 = "MLDSA44andECDSAP256";
    public static final String KEY_ALGO_MLDSA87andECDSAP384 = "MLDSA87andECDSAP384";
    public static final String KEY_ALGO_MLDSA87andECDSAP521 = "MLDSA87andECDSAP521";
    public static final String KEY_ALGO_Falcon512andECDSAP256 = "Falcon512andECDSAP256";
    public static final String KEY_ALGO_Falcon1024andECDSAP521 = "Falcon1024andECDSAP521";



    // Key formats

    /** Key format: "RAW". */
    public static final String KEY_FORMAT_RAW = "RAW";



    // Cipher modes

    /** Cipher mode: "ECB". */
    public static final String CIPHER_MODE_ECB = "ECB";

    /** Cipher mode: "CBC". */
    public static final String CIPHER_MODE_CBC = "CBC";

    /** Cipher mode: "GCM". */
    public static final String CIPHER_MODE_GCM = "GCM";



    // Cipher padding

    /** Cipher padding: "NoPadding". */
    public static final String CIPHER_PADDING_NONE = "NoPadding";

    /** Cipher padding: "ISO10126Padding". */
    public static final String CIPHER_PADDING_ISO10126 = "ISO10126Padding";

    /** Cipher padding: "PKCS1Padding". */
    public static final String CIPHER_PADDING_PKCS1 = "PKCS1Padding";

    /** Cipher padding: "OAEPPadding". */
    public static final String CIPHER_PADDING_OAEP = "OAEPPadding";



    // Symmetric key wrap algorithms

    /** Symmetric key wrap algorithm: "DESedeWrap". */
    public static final String KEYWRAP_ALGO_DESEDE = "DESedeWrap";

    /** Symmetric key wrap algorithm: "AESWrap". */
    public static final String KEYWRAP_ALGO_AES = "AESWrap";

    public static final String KEM_ALGO_CMCE = "CMCE";
    public static final String KEM_ALGO_KYBER = "KYBER";
    public static final String KEM_ALGO_BIKE = "BIKE";
    public static final String KEM_ALGO_HQC = "HQC";



    // Digest types

    /** Digest algorithm: "MD5". */
    public static final String DIGEST_MD5 = "MD5";

    /** Digest algorithm: "RIPEMD160". */
    public static final String DIGEST_RIPEMD160 = "RIPEMD160";

    /** Digest algorithm: "SHA-1". */
    public static final String DIGEST_SHA1 = "SHA-1";

    /** Digest algorithm: "SHA-224". */
    public static final String DIGEST_SHA224 = "SHA-224";

    /** Digest algorithm: "SHA-256". */
    public static final String DIGEST_SHA256 = "SHA-256";

    /** Digest algorithm: "SHA-384". */
    public static final String DIGEST_SHA384 = "SHA-384";

    /** Digest algorithm: "SHA-512". */
    public static final String DIGEST_SHA512 = "SHA-512";



    // Signature types

    /** Signature algorithm: "SHA1withDSA". */
    public static final String SIGNATURE_DSA_SHA1 = "SHA1withDSA";

    /** Signature algorithm: "SHA224withDSA". */
    public static final String SIGNATURE_DSA_SHA224 = "SHA224withDSA";

    /** Signature algorithm: "SHA256withDSA". */
    public static final String SIGNATURE_DSA_SHA256 = "SHA256withDSA";

    /** Signature algorithm: "MD5withRSA". */
    public static final String SIGNATURE_RSA_MD5 = "MD5withRSA";

    /** Signature algorithm: "RIPEMD160withRSA". */
    public static final String SIGNATURE_RSA_RIPEMD160 = "RIPEMD160withRSA";

    /** Signature algorithm: "SHA1withRSA". */
    public static final String SIGNATURE_RSA_SHA1 = "SHA1withRSA";

    /** Signature algorithm: "SHA224withRSA". */
    public static final String SIGNATURE_RSA_SHA224 = "SHA224withRSA";

    /** Signature algorithm: "SHA256withRSA". */
    public static final String SIGNATURE_RSA_SHA256 = "SHA256withRSA";

    /** Signature algorithm: "SHA384withRSA". */
    public static final String SIGNATURE_RSA_SHA384 = "SHA384withRSA";

    /** Signature algorithm: "SHA512withRSA". */
    public static final String SIGNATURE_RSA_SHA512 = "SHA512withRSA";

    /** Signature algorithm: "SHA1withECDSA". */
    public static final String SIGNATURE_ECDSA_SHA1 = "SHA1withECDSA";

    /** Signature algorithm: "SHA224withECDSA". */
    public static final String SIGNATURE_ECDSA_SHA224 = "SHA224withECDSA";

    /** Signature algorithm: "SHA256withECDSA". */
    public static final String SIGNATURE_ECDSA_SHA256 = "SHA256withECDSA";

    /** Signature algorithm: "SHA384withECDSA". */
    public static final String SIGNATURE_ECDSA_SHA384 = "SHA384withECDSA";

    /** Signature algorithm: "SHA512withECDSA". */
    public static final String SIGNATURE_ECDSA_SHA512 = "SHA512withECDSA";

    public static final String SIGNATURE_DILITHIUM = "Dilithium";
    public static final String SIGNATURE_FALCON = "Falcon";
    public static final String SIGNATURE_SPHINCSPLUS = "SPHINCSPlus";
    public static final String SIGNATURE_MLDSA44andECDSAP256 = "MLDSA44andECDSAP256";
    public static final String SIGNATURE_MLDSA87andECDSAP384 = "MLDSA87andECDSAP384";
    public static final String SIGNATURE_MLDSA87andECDSAP521 = "MLDSA87andECDSAP521";
    public static final String SIGNATURE_Falcon512andECDSAP256 = "Falcon512andECDSAP256";
    public static final String SIGNATURE_Falcon1024andECDSAP521 = "Falcon1024andECDSAP521";



    // MAC types

    /** MAC algorithm: "HmacMD5". */
    public static final String HMAC_MD5 = "HmacMD5";

    /** MAC algorithm: "HMACRIPEMD160". */
    public static final String HMAC_RIPEMD160 = "HMACRIPEMD160";

    /** MAC algorithm: "HmacSHA1". */
    public static final String HMAC_SHA1 = "HmacSHA1";

    /** MAC algorithm: "HmacSHA224". */
    public static final String HMAC_SHA224 = "HmacSHA224";

    /** MAC algorithm: "HmacSHA256". */
    public static final String HMAC_SHA256 = "HmacSHA256";

    /** MAC algorithm: "HmacSHA384". */
    public static final String HMAC_SHA384 = "HmacSHA384";

    /** MAC algorithm: "HmacSHA512". */
    public static final String HMAC_SHA512 = "HmacSHA512";



    // Key Agreement types

    /** Key Agreement algorithm: Diffie-Hellman. */
    public static final String KEY_AGREEMENT_DH = "DiffieHellman";

    /** Key Agreement algorithm: Elliptic Curve Diffie-Hellman. */
    public static final String KEY_AGREEMENT_ECDH = "ECDH";


    /** Constructor. Private to disable instantiation. */
    private JCAConstants() { }


}