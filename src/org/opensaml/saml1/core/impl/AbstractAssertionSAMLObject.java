/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opensaml.saml1.core.impl;

import org.opensaml.common.SAMLObject;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.AbstractSAMLObject;
import org.opensaml.common.xml.SAMLConstants;

/**
 * Base for SAML 1.X Assertion SAMLObject
 */
public abstract class AbstractAssertionSAMLObject extends AbstractSAMLObject {

    /**
     * Constructor. Sets namespace to {@link SAMLConstants#SAML1_NS} and prefix to
     * {@link SAMLConstants#SAML1_PREFIX}.  Sets the SAML version to {@link SAMLVersion#VERSION_11}.
     * 
     * @param localName the local name of the element
     * @deprecated
     */
    protected AbstractAssertionSAMLObject(String localName) {
        super(SAMLConstants.SAML1_NS, localName, SAMLConstants.SAML1_PREFIX);
        setSAMLVersion(SAMLObjectBuilder.getVersion(null));
    }

    /**
     * Constructor.  Sets the SAML version to {@link SAMLVersion#VERSION_11}.
     * 
     * @param namespaceURI the namespace the element is in
     * @param elementLocalName the local name of the XML element this Object represents
     * @param namespacePrefix the prefix for the given namespace
     * @deprecated
     */
    protected AbstractAssertionSAMLObject(String namespaceURI, String elementLocalName, String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
        setSAMLVersion(SAMLObjectBuilder.getVersion(null));
    }
    
    /**
     * Constructor. Sets namespace to {@link SAMLConstants#SAML1_NS} and prefix to
     * {@link SAMLConstants#SAML1_PREFIX}.  Sets the SAML version to {@link SAMLVersion#VERSION_11}.
     * 
     * @param localName the local name of the element
     * @param version the version for the element
     */
    protected AbstractAssertionSAMLObject(String localName, SAMLVersion version) {
        super(SAMLConstants.SAML1_NS, localName, SAMLConstants.SAML1_PREFIX);
        setSAMLVersion(version);
    }

    /**
     * Constructor.  Sets the SAML version to {@link SAMLVersion#VERSION_11}.
     * 
     * @param namespaceURI the namespace the element is in
     * @param elementLocalName the local name of the XML element this Object represents
     * @param namespacePrefix the prefix for the given namespace
     * @param version the version for the element
     */
    protected AbstractAssertionSAMLObject(String namespaceURI, String elementLocalName, String namespacePrefix, SAMLVersion version) {
        super(namespaceURI, elementLocalName, namespacePrefix);
        setSAMLVersion(version);    
    }

}