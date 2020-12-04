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
import org.opensaml.xmlsec.encryption.ConcatKDFParams;
import org.opensaml.xmlsec.encryption.XMLEncryptionBuilder;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;

/**
 * Builder of {@link org.opensaml.xmlsec.encryption.ConcatKDFParams}.
 */
public class ConcatKDFParamsBuilder extends AbstractXMLObjectBuilder<ConcatKDFParams>
        implements XMLEncryptionBuilder<ConcatKDFParams> {

    /**
     * Constructor.
     */
    public ConcatKDFParamsBuilder() {
    }

    /** {@inheritDoc} */
    public ConcatKDFParams buildObject(final String namespaceURI, final String localName,
            final String namespacePrefix) {
        return new ConcatKDFParamsImpl(namespaceURI, localName, namespacePrefix);
    }

    /** {@inheritDoc} */
    public ConcatKDFParams buildObject() {
        return buildObject(EncryptionConstants.XMLENC11_NS, ConcatKDFParams.DEFAULT_ELEMENT_LOCAL_NAME,
                EncryptionConstants.XMLENC11_PREFIX);
    }

}