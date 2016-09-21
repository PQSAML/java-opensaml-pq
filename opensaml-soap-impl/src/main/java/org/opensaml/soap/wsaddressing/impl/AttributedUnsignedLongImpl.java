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

package org.opensaml.soap.wsaddressing.impl;

import org.opensaml.core.xml.util.AttributeMap;
import org.opensaml.soap.wsaddressing.AttributedUnsignedLong;

/**
 * Implementation of {@link AttributedUnsignedLong}.
 */
public class AttributedUnsignedLongImpl extends AbstractWSAddressingObject implements AttributedUnsignedLong {
    
    /** Element's long value. */
    private Long value;
    
    /** Wildcard attributes. */
    private AttributeMap unknownAttributes;

    /**
     * Constructor.
     * 
     * @param namespaceURI The namespace of the element
     * @param elementLocalName The local name of the element
     * @param namespacePrefix The namespace prefix of the element
     */
    public AttributedUnsignedLongImpl(String namespaceURI, String elementLocalName, String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
        unknownAttributes = new AttributeMap(this);
    }

    /** {@inheritDoc} */
    public AttributeMap getUnknownAttributes() {
        return unknownAttributes;
    }

    /** {@inheritDoc} */
    public Long getValue() {
        return value;
    }

    /** {@inheritDoc} */
    public void setValue(Long newValue) {
        value = prepareForAssignment(value, newValue);
    }

}
