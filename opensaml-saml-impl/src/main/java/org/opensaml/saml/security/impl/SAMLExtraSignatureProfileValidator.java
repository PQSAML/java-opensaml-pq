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

package org.opensaml.saml.security.impl;

import com.google.common.base.Strings;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.impl.SignatureImpl;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignaturePrevalidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.annotation.Nonnull;

/**
 * A validator for instances of {@link Signature}, which validates that the signature meets security-related
 * requirements indicated by the SAML profile of XML Signature.
 */
public class SAMLExtraSignatureProfileValidator extends SAMLSignatureProfileValidator{

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(SAMLExtraSignatureProfileValidator.class);

    /** {@inheritDoc} */
    @Override
    protected void validateSignatureImpl(final SignatureImpl sigImpl) throws SignatureException {

        if (sigImpl.getXMLSignature() == null) {
            log.error("SignatureImpl did not contain the an Apache XMLSignature child");
            throw new SignatureException("Apache XMLSignature does not exist on SignatureImpl");
        }
        final XMLSignature apacheSig = sigImpl.getXMLSignature();

        if (!(sigImpl.getParent() instanceof Extensions || sigImpl.getParent().getParent() instanceof SignableSAMLObject)) {
            log.error("Signature is not an immediate child of Extensions that is an immediate child of a SignableSAMLObject");
            throw new SignatureException("Signature is not an immediate child of Extensions that is an immediate child of a SignableSAMLObject.");
        }
        final SignableSAMLObject signableObject = (SignableSAMLObject) sigImpl.getParent().getParent();

        final Reference ref = validateReference(apacheSig);

        validateReferenceURI(ref.getURI(), signableObject);

        validateTransforms(ref);

        validateObjectChildren(apacheSig);
    }

    /** {@inheritDoc} */
    @Override
    protected void validateTransforms(final Reference reference) throws SignatureException {
        Transforms transforms = null;
        try {
            transforms = reference.getTransforms();
        } catch (final XMLSecurityException e) {
            log.error("Apache XML Security error obtaining Transforms instance: {}", e.getMessage());
            throw new SignatureException("Apache XML Security error obtaining Transforms instance", e);
        }

        if (transforms == null) {
            log.error("Error obtaining Transforms instance, null was returned");
            throw new SignatureException("Transforms instance was null");
        }

        final int numTransforms = transforms.getLength();
        if (numTransforms > 3) {
            log.error("Invalid number of Transforms was present: " + numTransforms);
            throw new SignatureException("Invalid number of transforms");
        }

        boolean sawEnveloped = false;
        for (int i = 0; i < numTransforms; i++) {
            Transform transform = null;
            try {
                transform = transforms.item(i);
            } catch (final TransformationException e) {
                log.error("Error obtaining transform instance: {}", e.getMessage());
                throw new SignatureException("Error obtaining transform instance", e);
            }
            final String uri = transform.getURI();
            if (Transforms.TRANSFORM_ENVELOPED_SIGNATURE.equals(uri)) {
                log.debug("Saw Enveloped signature transform");
                sawEnveloped = true;
            } else if (Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS.equals(uri)
                    || Transforms.TRANSFORM_C14N_EXCL_WITH_COMMENTS.equals(uri)) {
                log.debug("Saw Exclusive C14N signature transform");
            } else if (Transforms.TRANSFORM_XPATH2FILTER.equals(uri) && transform.getElement().getTextContent().trim().equals(
                    SignatureConstants.EXTRA_SIGNATURE_XPATH2_FILTER)) {
                log.debug("Saw XPath Filter 2 transform");
            } else {
                log.error("Saw invalid signature transform: " + uri);
                throw new SignatureException("Signature contained an invalid transform");
            }
        }

        if (!sawEnveloped) {
            log.error("Signature was missing the required Enveloped signature transform");
            throw new SignatureException("Transforms did not contain the required enveloped transform");
        }
    }
}