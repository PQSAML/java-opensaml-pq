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

package org.opensaml.xmlsec.signature.support;

import org.opensaml.xmlsec.encryption.support.EncryptionConstants;

/**
 * Constants defined in or related to the XML Signature 1.0 and 1.1 specifications and
 * related RFCs.
 */
public final class SignatureConstants {

    /** XML Signature namespace and algorithm prefix. */
    public static final String XMLSIG_NS = "http://www.w3.org/2000/09/xmldsig#";

    /** XML Signature 1.1 namespace and algorithm prefix. */
    public static final String XMLSIG11_NS = "http://www.w3.org/2009/xmldsig11#";
    
    /** XML Signature QName prefix. */
    public static final String XMLSIG_PREFIX = "ds";
    
    /** XML Signature 1.1 QName prefix. */
    public static final String XMLSIG11_PREFIX = "ds11";

    /** Algorithm URI prefix used by RFC 4051. */
    public static final String MORE_ALGO_NS = "http://www.w3.org/2001/04/xmldsig-more#";

    // *********************************************************
    // Algorithm URI's
    // *********************************************************

    /** Signature - Optional DSAwithSHA1 (DSS). */
    public static final String ALGO_ID_SIGNATURE_DSA = XMLSIG_NS + "dsa-sha1";

    /** Signature - Optional DSAwithSHA1 (DSS). */
    public static final String ALGO_ID_SIGNATURE_DSA_SHA1 = ALGO_ID_SIGNATURE_DSA;
    
    /** Signature - Required RSAwithSHA1 (PKCS1). */
    public static final String ALGO_ID_SIGNATURE_RSA = XMLSIG_NS + "rsa-sha1";

    /** Signature - Required RSAwithSHA1 (PKCS1). */
    public static final String ALGO_ID_SIGNATURE_RSA_SHA1 = ALGO_ID_SIGNATURE_RSA;

    /** MAC - Required HMAC-SHA1. */
    public static final String ALGO_ID_MAC_HMAC_SHA1 = XMLSIG_NS + "hmac-sha1";

    /** Digest - Required SHA1. */
    public static final String ALGO_ID_DIGEST_SHA1 = XMLSIG_NS + "sha1";

    /** Encoding - Required Base64. */
    public static final String ALGO_ID_ENCODING_BASE64 = XMLSIG_NS + "base64";

    // *********************************************************
    // URI's representing types that may be dereferenced, such
    // as in RetrievalMethod/@Type
    // *********************************************************

    /** Type - KeyInfo DSAKeyValue. */
    public static final String TYPE_KEYINFO_DSA_KEYVALUE = XMLSIG_NS + "DSAKeyValue";

    /** Type - KeyInfo RSAKeyValue. */
    public static final String TYPE_KEYINFO_RSA_KEYVALUE = XMLSIG_NS + "RSAKeyValue";

    /** Type - KeyInfo X509Data. */
    public static final String TYPE_KEYINFO_X509DATA = XMLSIG_NS + "X509Data";

    /** Type - KeyInfo PGPData. */
    public static final String TYPE_KEYINFO_PGPDATA = XMLSIG_NS + "PGPData";

    /** Type - KeyInfo SPKIData. */
    public static final String TYPE_KEYINFO_SPKIDATA = XMLSIG_NS + "SPKIData";

    /** Type - KeyInfo MgmtData. */
    public static final String TYPE_KEYINFO_MGMTDATA = XMLSIG_NS + "MgmtData";

    /** Type - A binary (ASN.1 DER) X.509 Certificate. */
    public static final String TYPE_KEYINFO_RAW_X509CERT = XMLSIG_NS + "rawX509Certificate";

    /** Type - Signature Object. */
    // public static final String TYPE_SIGNATURE_OBJECT = XMLSIG_NS + "Object";

    /** Type - Signature Manifest. */
    // public static final String TYPE_SIGNATURE_MANIFEST = XMLSIG_NS + "Manifest";

    /** Type - Signature SignatureProperties. */
    // public static final String TYPE_SIGNATURE_SIGNATURE_PROPERTIES = XMLSIG_NS + "SignatureProperties";

    // These are additional type URIs defined by RFC 4051

    /** Type - KeyInfo KeyValue. */
    public static final String TYPE_KEYINFO_KEYVALUE = MORE_ALGO_NS + "KeyValue";

    /** Type - KeyInfo RetrievalMethod. */
    public static final String TYPE_KEYINFO_RETRIEVAL_METHOD = MORE_ALGO_NS + "RetrievalMethod";

    /** Type - KeyInfo KeyName. */
    public static final String TYPE_KEYINFO_KEYNAME = MORE_ALGO_NS + "KeyName";

    /** Type - A binary X.509 CRL. */
    public static final String TYPE_KEYINFO_RAW_X509CRL = MORE_ALGO_NS + "rawX509CRL";

    /** Type - A binary PGP key packet. */
    public static final String TYPE_KEYINFO_RAW_PGP_KEYPACKET = MORE_ALGO_NS + "rawPGPKeyPacket";

    /** Type - A raw SPKI S-expression. */
    public static final String TYPE_KEYINFO_RAW_SPKI_SEXP = MORE_ALGO_NS + "rawSPKISexp";

    /** Type - A PKCS7signedData element. */
    public static final String TYPE_KEYINFO_PKCS7_SIGNED_DATA = MORE_ALGO_NS + "PKCS7signedData";

    /** Type - Binary PKCS7 signed data. */
    public static final String TYPE_KEYINFO_RAW_PKCS7_SIGNED_DATA = MORE_ALGO_NS + "rawPKCS7signedData";

    // These are additional type URIs defined by XML Signature 1.1
    
    /** Type - KeyInfo ECKeyValue. */
    public static final String TYPE_KEYINFO_ECKEYVALUE = XMLSIG11_NS + "ECKeyValue";
    
    /** Type - KeyInfo DEREncodedKeyValue. */
    public static final String TYPE_KEYINFO_DERENCODEDKEYVALUE = XMLSIG11_NS + "DEREncodedKeyValue";
    
    
    // *********************************************************
    // Canonicalization
    // *********************************************************

    /** Canonicalization - Inclusive 1.0 WITHOUT comments. */
    public static final String ALGO_ID_C14N_OMIT_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

    /** Canonicalization - Inclusive 1.0 WITH comments. */
    public static final String ALGO_ID_C14N_WITH_COMMENTS = ALGO_ID_C14N_OMIT_COMMENTS + "#WithComments";

    /** Canonicalization - Inclusive 1.1 WITHOUT comments. */
    public static final String ALGO_ID_C14N11_OMIT_COMMENTS = "http://www.w3.org/2006/12/xml-c14n11";

    /** Canonicalization - Inclusive 1.1 WITH comments. */
    public static final String ALGO_ID_C14N11_WITH_COMMENTS = ALGO_ID_C14N11_OMIT_COMMENTS + "#WithComments";
    
    /** Canonicalization - Exclusive WITHOUT comments. */
    public static final String ALGO_ID_C14N_EXCL_OMIT_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#";

    /** Canonicalization - Exclusive WITH comments. */
    public static final String ALGO_ID_C14N_EXCL_WITH_COMMENTS = ALGO_ID_C14N_EXCL_OMIT_COMMENTS + "WithComments";

    // *********************************************************
    // Transforms
    // *********************************************************

    /** Transform - Required Enveloped Signature. */
    public static final String TRANSFORM_ENVELOPED_SIGNATURE = XMLSIG_NS + "enveloped-signature";

    /** Transform - Required Inclusive c14n 1.0 WITHOUT comments. */
    public static final String TRANSFORM_C14N_OMIT_COMMENTS = ALGO_ID_C14N_OMIT_COMMENTS;

    /** Transform - Recommended Inclusive c14n 1.0 WITH comments. */
    public static final String TRANSFORM_C14N_WITH_COMMENTS = ALGO_ID_C14N_WITH_COMMENTS;

    /** Transform - Required Inclusive c14n 1.1 WITHOUT comments. */
    public static final String TRANSFORM_C14N11_OMIT_COMMENTS = ALGO_ID_C14N11_OMIT_COMMENTS;

    /** Transform - Recommended Inclusive c14n 1.1 WITH comments. */
    public static final String TRANSFORM_C14N11_WITH_COMMENTS = ALGO_ID_C14N11_WITH_COMMENTS;
    
    /** Transform - Required Exclusive c14n WITHOUT comments. */
    public static final String TRANSFORM_C14N_EXCL_OMIT_COMMENTS = ALGO_ID_C14N_EXCL_OMIT_COMMENTS;

    /** Transform - Recommended Exclusive c14n WITH comments. */
    public static final String TRANSFORM_C14N_EXCL_WITH_COMMENTS = ALGO_ID_C14N_EXCL_WITH_COMMENTS;

    /** Transform - Optional XSLT. */
    public static final String TRANSFORM_XSLT = "http://www.w3.org/TR/1999/REC-xslt-19991116";

    /** Transform - Recommended XPath. */
    public static final String TRANSFORM_XPATH = "http://www.w3.org/TR/1999/REC-xpath-19991116";

    /** Transform - Base64 Decode. */
    public static final String TRANSFORM_BASE64_DECODE = XMLSIG_NS + "base64";

    /*
     * public static final String TRANSFORM_XPOINTER = "http://www.w3.org/TR/2001/WD-xptr-20010108"; public static final
     * String TRANSFORM_XPATH2FILTER04 = "http://www.w3.org/2002/04/xmldsig-filter2"; public static final String
     * TRANSFORM_XPATH2FILTER = "http://www.w3.org/2002/06/xmldsig-filter2";
     */

    // *********************************************************
    // Some additional algorithm URIs from RFC 4051
    // *********************************************************
    /** Signature - NOT Recommended RSAwithMD5. */
    public static final String ALGO_ID_SIGNATURE_NOT_RECOMMENDED_RSA_MD5 = MORE_ALGO_NS + "rsa-md5";

    /** Signature - Optional RSAwithRIPEMD160. */
    public static final String ALGO_ID_SIGNATURE_RSA_RIPEMD160 = MORE_ALGO_NS + "rsa-ripemd160";

    /** Signature - Required RSAwithSHA256. */
    public static final String ALGO_ID_SIGNATURE_RSA_SHA256 = MORE_ALGO_NS + "rsa-sha256";

    /** Signature - Optional RSAwithSHA224. */
    public static final String ALGO_ID_SIGNATURE_RSA_SHA224 = MORE_ALGO_NS + "rsa-sha224";

    /** Signature - Required RSAwithSHA384. */
    public static final String ALGO_ID_SIGNATURE_RSA_SHA384 = MORE_ALGO_NS + "rsa-sha384";

    /** Signature - Required RSAwithSHA512. */
    public static final String ALGO_ID_SIGNATURE_RSA_SHA512 = MORE_ALGO_NS + "rsa-sha512";

    /** HMAC - NOT Recommended HMAC-MD5. */
    public static final String ALGO_ID_MAC_HMAC_NOT_RECOMMENDED_MD5 = MORE_ALGO_NS + "hmac-md5";

    /** HMAC - Optional HMAC-RIPEMD160. */
    public static final String ALGO_ID_MAC_HMAC_RIPEMD160 = MORE_ALGO_NS + "hmac-ripemd160";

    /** HMAC - Optional HMAC-SHA224. */
    public static final String ALGO_ID_MAC_HMAC_SHA224 = MORE_ALGO_NS + "hmac-sha224";
    
    /** HMAC - Optional HMAC-SHA256. */
    public static final String ALGO_ID_MAC_HMAC_SHA256 = MORE_ALGO_NS + "hmac-sha256";

    /** HMAC - Optional HMAC-SHA284. */
    public static final String ALGO_ID_MAC_HMAC_SHA384 = MORE_ALGO_NS + "hmac-sha384";

    /** HMAC - Optional HMAC-SHA512. */
    public static final String ALGO_ID_MAC_HMAC_SHA512 = MORE_ALGO_NS + "hmac-sha512";

    /** Signature - Optional ECDSAwithSHA1. */
    public static final String ALGO_ID_SIGNATURE_ECDSA_SHA1 = MORE_ALGO_NS + "ecdsa-sha1";

    /** Signature - Optional ECDSAwithSHA224. */
    public static final String ALGO_ID_SIGNATURE_ECDSA_SHA224 = MORE_ALGO_NS + "ecdsa-sha224";

    /** Signature - Optional ECDSAwithSHA256. */
    public static final String ALGO_ID_SIGNATURE_ECDSA_SHA256 = MORE_ALGO_NS + "ecdsa-sha256";

    /** Signature - Optional ECDSAwithSHA384. */
    public static final String ALGO_ID_SIGNATURE_ECDSA_SHA384 = MORE_ALGO_NS + "ecdsa-sha384";

    /** Signature - Optional ECDSAwithSHA512. */
    public static final String ALGO_ID_SIGNATURE_ECDSA_SHA512 = MORE_ALGO_NS + "ecdsa-sha512";
    
    /** Digest - Optional MD5. */
    public static final String ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5 = MORE_ALGO_NS + "md5";

    /** Digest - Optional SHA224. */
    public static final String ALGO_ID_DIGEST_SHA224 = MORE_ALGO_NS + "sha224";

    /** Digest - Optional SHA384. */
    public static final String ALGO_ID_DIGEST_SHA384 = MORE_ALGO_NS + "sha384";
    
    // *********************************************************
    // Some additional algorithm URIs from XML Signature 1.1
    // *********************************************************
    /** Signature - Optional DSAwithSHA256 (DSS). */
    public static final String ALGO_ID_SIGNATURE_DSA_SHA256 = XMLSIG11_NS + "dsa-sha256";
    
    // *********************************************************
    // Alias in some additional algorithm URI's used in XML 
    // Signature, but defined in XML Encryption.
    // *********************************************************
    /** Message Digest - SHA256 (Note: Defined by XML Encryption). */
    public static final String ALGO_ID_DIGEST_SHA256 = EncryptionConstants.ALGO_ID_DIGEST_SHA256;
    
    /** Message Digest - SHA512 (Note: Defined by XML Encryption). */
    public static final String ALGO_ID_DIGEST_SHA512 = EncryptionConstants.ALGO_ID_DIGEST_SHA512;
    
    /** Message Digest - RIPEMD-160 (Note: Defined by XML Encryption). */
    public static final String ALGO_ID_DIGEST_RIPEMD160 = EncryptionConstants.ALGO_ID_DIGEST_RIPEMD160;
    
    
    /** Constructor. */
    private SignatureConstants() {

    }
}