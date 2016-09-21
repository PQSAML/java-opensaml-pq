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

package org.opensaml.xmlsec.encryption;

import javax.annotation.Nullable;
import javax.xml.namespace.QName;

import org.opensaml.core.xml.ElementExtensibleXMLObject;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;

/**
 * XMLObject representing XML Encryption, version 20021210, ReferenceType type. This is the base type for
 * {@link DataReference} and {@link KeyReference} types.
 */
public interface ReferenceType extends ElementExtensibleXMLObject {

    /** Local name of the XSI type. */
    public static final String TYPE_LOCAL_NAME = "ReferenceType";

    /** QName of the XSI type. */
    public static final QName TYPE_NAME = new QName(EncryptionConstants.XMLENC_NS, TYPE_LOCAL_NAME,
            EncryptionConstants.XMLENC_PREFIX);

    /** URI attribute name. */
    public static final String URI_ATTRIB_NAME = "URI";

    /**
     * Get the URI attribute which indicates the referent of this reference.
     * 
     * @return the URI referent attribute value
     */
    @Nullable public String getURI();

    /**
     * Set the URI attribute which indicates the referent of this reference.
     * 
     * @param newURI the new URI attribute value
     */
    public void setURI(@Nullable final String newURI);

}