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

/**
 * 
 */

package org.opensaml.saml2.metadata.impl;

import org.opensaml.common.SAMLObjectUnmarshaller;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.SingleLogoutService;

/**
 * A thread safe {@link org.opensaml.common.io.Unmarshaller} for {@link org.opensaml.saml2.metadata.SingleLogoutService}
 * objects.
 */
public class SingleLogoutServiceUnmarshaller extends EndpointUnmarshaller implements SAMLObjectUnmarshaller {

    /**
     * Constructor
     */
    public SingleLogoutServiceUnmarshaller() {
        super(SAMLConstants.SAML20MD_NS, SingleLogoutService.LOCAL_NAME);
    }
}