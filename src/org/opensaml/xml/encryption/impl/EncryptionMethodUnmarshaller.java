/*
 * Copyright [2006] [University Corporation for Advanced Internet Development, Inc.]
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

package org.opensaml.xml.encryption.impl;

import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.EncryptionMethod;
import org.opensaml.xml.encryption.KeySize;
import org.opensaml.xml.encryption.OAEPparams;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.util.XMLConstants;
import org.w3c.dom.Attr;

/**
 * A thread-safe Unmarshaller for {@link org.opensaml.xml.encryption.EncryptionMethod} objects.
 */
public class EncryptionMethodUnmarshaller extends AbstractXMLEncryptionUnmarshaller {
    
    /**
     * Constructor
     *
     */
    public EncryptionMethodUnmarshaller() throws UnmarshallingException{
        super(XMLConstants.XMLENC_NS, EncryptionMethod.DEFAULT_ELEMENT_LOCAL_NAME);
    }

    /**
     * Constructor
     *
     * @param targetNamespaceURI
     * @param targetLocalName
     * @throws IllegalArgumentException
     */
    public EncryptionMethodUnmarshaller(String targetNamespaceURI, String targetLocalName)
            throws UnmarshallingException {
        super(targetNamespaceURI, targetLocalName);
    }

    /** {@inheritDoc} */
    protected void processAttribute(XMLObject xmlObject, Attr attribute) throws UnmarshallingException {
        EncryptionMethod em = (EncryptionMethod) xmlObject;
        
        if (attribute.getLocalName().equals((EncryptionMethod.ALGORITHM_ATTRIB_NAME))) {
            em.setAlgorithm(attribute.getValue());
        } else {
            super.processAttribute(xmlObject, attribute);
        }
    }

    /** {@inheritDoc} */
    protected void processChildElement(XMLObject parentXMLObject, XMLObject childXMLObject) throws UnmarshallingException {
        EncryptionMethod em = (EncryptionMethod) parentXMLObject;
        if (childXMLObject instanceof KeySize) {
            em.setKeySize((KeySize) childXMLObject);
        } else if (childXMLObject instanceof OAEPparams) {
            em.setOAEPparams((OAEPparams) childXMLObject);
        } else {
            em.getUnknownXMLObjects().add(childXMLObject);
        }
    }

}
