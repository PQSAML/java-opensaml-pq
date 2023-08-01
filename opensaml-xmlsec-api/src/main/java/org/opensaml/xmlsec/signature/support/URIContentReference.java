/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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

import java.util.LinkedList;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;
import org.slf4j.Logger;

import net.shibboleth.shared.annotation.constraint.Live;
import net.shibboleth.shared.primitive.LoggerFactory;
import net.shibboleth.shared.primitive.StringSupport;

/**
 * A generic content reference that uses a URI to reference the content to be signed.
 * 
 * <p>
 * The default digest algorithm used is {@link SignatureConstants#ALGO_ID_DIGEST_SHA256}.
 * </p>
 */
public class URIContentReference implements ConfigurableContentReference, TransformsConfigurableContentReference {

    /** Logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(URIContentReference.class);

    /** Element reference ID. */
    @Nullable private final String referenceID;

    /** Algorithm used to digest the content . */
    @Nullable private String digestAlgorithm;

    /** Transforms applied to the content. */
    @Nonnull private final List<String> transforms;

    /**
     * Constructor. The anchor designator (#) must not be included in the ID.
     * 
     * @param refID the reference ID of the element to be signed
     */
    public URIContentReference(@Nullable final String refID) {
        referenceID = refID;
        transforms = new LinkedList<>();
        
        // Set defaults
        digestAlgorithm = SignatureConstants.ALGO_ID_DIGEST_SHA256;
    }

    /**
     * Gets the transforms applied to the content prior to digest generation.
     * 
     * @return the transforms applied to the content prior to digest generation
     */
    @Nonnull @Live public List<String> getTransforms() {
        return transforms;
    }

    /** {@inheritDoc}. */
    @Nullable public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /** {@inheritDoc}. */
    public void setDigestAlgorithm(@Nullable final String newAlgorithm) {
        digestAlgorithm = StringSupport.trimOrNull(newAlgorithm);
    }

    /** {@inheritDoc} */
    public void createReference(@Nonnull final XMLSignature signature) {
        try {
            final Transforms dsigTransforms = new Transforms(signature.getDocument());
            for (final String transform : getTransforms()) {
                dsigTransforms.addTransform(transform);
            }
            signature.addDocument(referenceID, dsigTransforms, digestAlgorithm);
        } catch (final TransformationException e) {
            log.error("Error while creating transforms", e);
        } catch (final XMLSignatureException e) {
            log.error("Error while adding content reference", e);
        }
    }
    
}