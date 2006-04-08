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

import java.util.List;

import org.opensaml.common.impl.AbstractSAMLObject;
import org.opensaml.saml1.core.SubjectLocality;
import org.opensaml.xml.XMLObject;

/**
 * A concrete impementation of the {@link org.opensaml.saml1.core.SubjectLocality} interface
 */
public class SubjectLocalityImpl extends AbstractSAMLObject implements SubjectLocality {

    /** The ipAddress */
    private String ipAddress;

    /** The DNS Address */
    private String dnsAddress;

    /**
     * Constructor
     * 
     * @param namespaceURI the namespace the element is in
     * @param elementLocalName the local name of the XML element this Object represents
     * @param namespacePrefix the prefix for the given namespace
     */
    protected SubjectLocalityImpl(String namespaceURI, String elementLocalName, String namespacePrefix) {
        super(namespaceURI, elementLocalName, namespacePrefix);
    }

    /*
     * @see org.opensaml.saml1.core.SubjectLocality#getIPAddress()
     */
    public String getIPAddress() {
        return ipAddress;
    }

    /*
     * @see org.opensaml.saml1.core.SubjectLocality#setIPAddress(java.lang.String)
     */
    public void setIPAddress(String address) {
        ipAddress = prepareForAssignment(ipAddress, address);
    }

    /*
     * @see org.opensaml.saml1.core.SubjectLocality#getDNSAddress()
     */
    public String getDNSAddress() {
        return dnsAddress;
    }

    /*
     * @see org.opensaml.saml1.core.SubjectLocality#setDNSAddress(java.lang.String)
     */
    public void setDNSAddress(String address) {
        dnsAddress = prepareForAssignment(dnsAddress, address);
    }

    /*
     * @see org.opensaml.xml.XMLObject#getOrderedChildren()
     */
    public List<XMLObject> getOrderedChildren() {
        // No children
        return null;
    }
}