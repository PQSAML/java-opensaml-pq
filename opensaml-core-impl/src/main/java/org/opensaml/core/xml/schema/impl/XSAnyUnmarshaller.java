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

package org.opensaml.core.xml.schema.impl;

import javax.annotation.Nonnull;
import javax.xml.namespace.QName;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.AbstractXMLObjectUnmarshaller;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.w3c.dom.Attr;

import net.shibboleth.shared.xml.QNameSupport;

/**
 * A thread-safe unmarshaller for {@link XSAny}s.
 */
public class XSAnyUnmarshaller extends AbstractXMLObjectUnmarshaller {

    /** {@inheritDoc} */
    @Override
    protected void processChildElement(@Nonnull final XMLObject parentXMLObject,
            @Nonnull final XMLObject childXMLObject) throws UnmarshallingException {
        final XSAny xsAny = (XSAny) parentXMLObject;

        xsAny.getUnknownXMLObjects().add(childXMLObject);
    }

    /** {@inheritDoc} */
    @Override
    protected void processAttribute(@Nonnull final XMLObject xmlObject, @Nonnull final Attr attribute)
            throws UnmarshallingException {
        final XSAny xsAny = (XSAny) xmlObject;

        final QName attribQName = QNameSupport.getNodeQName(attribute);
        
        if (attribute.isId()) {
            xsAny.getUnknownAttributes().registerID(attribQName);
        }

        xsAny.getUnknownAttributes().put(attribQName, attribute.getValue());
    }

    /** {@inheritDoc} */
    @Override
    protected void processElementContent(@Nonnull final XMLObject xmlObject, @Nonnull final String elementContent) {
        final XSAny xsAny = (XSAny) xmlObject;

        xsAny.setTextContent(elementContent);
    }
    
}