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

import org.opensaml.core.xml.AbstractXMLObject;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.xmlsec.signature.X509Certificate;

import net.shibboleth.utilities.java.support.collection.IndexingObjectStore;
import net.shibboleth.utilities.java.support.primitive.CleanerSupport;

/** Concrete implementation of {@link X509Certificate}. */
public class X509CertificateImpl extends AbstractXMLObject implements X509Certificate {

    /** Class-level index of Base64 encoded cert values. */
    private static final IndexingObjectStore<String> B64_CERT_STORE = new IndexingObjectStore<>();

    /** The {@link Cleaner} instance to use. */
    private static final Cleaner CLEANER = CleanerSupport.getInstance(X509CertificateImpl.class);

    /** The {@link Cleanable} representing the current instance's cert value, as represented by the
     * current <code>b64CertIndex</code> field value. */
    private Cleaner.Cleanable cleanable;

    /** Index to a stored Base64 encoded cert. */
    private String b64CertIndex;

    /**
     * Constructor.
     * 
     * @param namespaceURI the namespace the element is in
     * @param elementLocalName the local name of the XML element this Object represents
     * @param namespacePrefix the prefix for the given namespace
     */
    protected X509CertificateImpl(final String namespaceURI, final String elementLocalName,
            final String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }

    /** {@inheritDoc} */
    @Override
    public String getValue() {
        return B64_CERT_STORE.get(b64CertIndex);
    }

    /** {@inheritDoc} */
    @Override
    public void setValue(final String newValue) {
        // Dump our cached DOM if the new value really is new
        final String currentCert = B64_CERT_STORE.get(b64CertIndex);
        final String newCert = prepareForAssignment(currentCert, newValue);

        // This is a new value, remove the old one, add the new one
        if (!Objects.equals(currentCert, newCert)) {
            if (cleanable != null) {
                cleanable.clean();
                cleanable = null;
            }
            b64CertIndex = B64_CERT_STORE.put(newCert);
            if (b64CertIndex != null) {
                cleanable = CLEANER.register(this, new CleanerState(b64CertIndex));
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
            X509CertificateImpl.B64_CERT_STORE.remove(index);
        }

    }

}