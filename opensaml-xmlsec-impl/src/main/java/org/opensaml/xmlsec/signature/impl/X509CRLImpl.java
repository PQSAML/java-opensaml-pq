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

package org.opensaml.xmlsec.signature.impl;

import java.lang.ref.Cleaner;
import java.lang.ref.Cleaner.Cleanable;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.collection.IndexingObjectStore;
import net.shibboleth.utilities.java.support.primitive.CleanerSupport;

import org.opensaml.core.xml.AbstractXMLObject;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.xmlsec.signature.X509CRL;

/** Concrete implementation of {@link X509CRL}. */
public class X509CRLImpl extends AbstractXMLObject implements X509CRL {

    /** Class-level index of Base64 encoded CRL values. */
    private static final IndexingObjectStore<String> B64_CRL_STORE = new IndexingObjectStore<>();

    /** The {@link Cleaner} instance to use. */
    private static final Cleaner CLEANER = CleanerSupport.getInstance(X509CRLImpl.class);

    /** The {@link Cleanable} representing the current instance's CRL value, as represented by the
     * current <code>b64CRLIndex</code> field value. */
    private Cleaner.Cleanable cleanable;

    /** Index to a stored Base64 encoded CRL. */
    private String b64CRLIndex;

    /**
     * Constructor.
     * 
     * @param namespaceURI the namespace the element is in
     * @param elementLocalName the local name of the XML element this Object represents
     * @param namespacePrefix the prefix for the given namespace
     */
    protected X509CRLImpl(final String namespaceURI, final String elementLocalName, final String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }

    /** {@inheritDoc} */
    public String getValue() {
        return B64_CRL_STORE.get(b64CRLIndex);
    }

    /** {@inheritDoc} */
    public void setValue(final String newValue) {
        // Dump our cached DOM if the new value really is new
        final String currentCRL = B64_CRL_STORE.get(b64CRLIndex);
        final String newCRL = prepareForAssignment(currentCRL, newValue);

        // This is a new value, remove the old one, add the new one
        if (!Objects.equals(currentCRL, newCRL)) {
            if (cleanable != null) {
                cleanable.clean();
                cleanable = null;
            }
            b64CRLIndex = B64_CRL_STORE.put(newCRL);
            if (b64CRLIndex != null) {
                cleanable = CLEANER.register(this, new CleanerState(b64CRLIndex));
            }
        }
    }

    /** {@inheritDoc} */
    @Override
    public List<XMLObject> getOrderedChildren() {
        return Collections.emptyList();
    }

    /**
     * The action to be taken when the current state must be cleaned.
     */
    static class CleanerState implements Runnable {

        /** The index to remove from the store. */
        private String index;

        /**
         * Constructor.
         *
         * @param idx the index in the {@link X509CertificateImpl#B64_CERT_STORE}.
         */
        public CleanerState(@Nonnull final String idx) {
            index = idx;
        }

        /** {@inheritDoc} */
        public void run() {
            X509CRLImpl.B64_CRL_STORE.remove(index);
        }

    }
}