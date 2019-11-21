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

/**
 * 
 */

package org.opensaml.saml.saml2.core;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;

import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.xml.SAMLConstants;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/**
 * SAML 2.0 Core SessionIndex.
 */
public interface SessionIndex extends SAMLObject {

    /** Element local name. */
    @Nonnull @NotEmpty static final String DEFAULT_ELEMENT_LOCAL_NAME = "SessionIndex";

    /** Default element name. */
    @Nonnull static final QName DEFAULT_ELEMENT_NAME = new QName(SAMLConstants.SAML20P_NS, DEFAULT_ELEMENT_LOCAL_NAME,
            SAMLConstants.SAML20P_PREFIX);

    /**
     * Gets the session index value of the request.
     * 
     * @return the session index value of the request
     */
    @Nullable String getValue();

    /**
     * Sets the session index value of the request.
     * 
     * @param value the new session index value of the request
     */
    void setValue(@Nullable final String value);

    /**
     * Gets the session index value of the request.
     * 
     * @return the session index value of the request
     * 
     * @deprecated
     */
    @Nullable default String getSessionIndex() {
        return getValue();
    }

    /**
     * Sets the session index value of the request.
     * 
     * @param value the new session index value of the request
     * 
     * @deprecated
     */
    default void setSessionIndex(@Nullable final String value) {
        setValue(value);
    }

}