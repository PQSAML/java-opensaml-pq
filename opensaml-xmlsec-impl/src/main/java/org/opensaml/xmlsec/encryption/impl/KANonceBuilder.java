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

package org.opensaml.xmlsec.encryption.impl;

import org.opensaml.core.xml.AbstractXMLObjectBuilder;
import org.opensaml.xmlsec.encryption.KANonce;
import org.opensaml.xmlsec.encryption.XMLEncryptionBuilder;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;

/**
 * Builder of {@link org.opensaml.xmlsec.encryption.KANonce}.
 */
public class KANonceBuilder extends AbstractXMLObjectBuilder<KANonce> implements XMLEncryptionBuilder<KANonce> {

    /**
     * Constructor.
     */
    public KANonceBuilder() {
    }

    /** {@inheritDoc} */
    public KANonce buildObject(String namespaceURI, String localName, String namespacePrefix) {
        return new KANonceImpl(namespaceURI, localName, namespacePrefix);
    }

    /** {@inheritDoc} */
    public KANonce buildObject() {
        return buildObject(EncryptionConstants.XMLENC_NS, KANonce.DEFAULT_ELEMENT_LOCAL_NAME,
                EncryptionConstants.XMLENC_PREFIX);
    }

}