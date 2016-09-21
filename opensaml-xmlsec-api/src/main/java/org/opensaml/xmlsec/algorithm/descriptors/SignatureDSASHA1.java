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

package org.opensaml.xmlsec.algorithm.descriptors;

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

import org.opensaml.security.crypto.JCAConstants;
import org.opensaml.xmlsec.algorithm.SignatureAlgorithm;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

/**
 * Algorithm descriptor for signature algorithm: DSA SHA-1.
 */
public final class SignatureDSASHA1 implements SignatureAlgorithm {

    /** {@inheritDoc} */
    @Nonnull @NotEmpty public String getKey() {
        return JCAConstants.KEY_ALGO_DSA;
    }

    /** {@inheritDoc} */
    @Nonnull @NotEmpty public String getURI() {
        return SignatureConstants.ALGO_ID_SIGNATURE_DSA_SHA1;
    }

    /** {@inheritDoc} */
    @Nonnull public AlgorithmType getType() {
        return AlgorithmType.Signature;
    }

    /** {@inheritDoc} */
    @Nonnull @NotEmpty public String getJCAAlgorithmID() {
        return JCAConstants.SIGNATURE_DSA_SHA1;
    }

    /** {@inheritDoc} */
    @Nonnull @NotEmpty public String getDigest() {
        return JCAConstants.DIGEST_SHA1;
    }

}
