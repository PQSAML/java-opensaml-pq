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

package org.opensaml.messaging.context.navigate;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;

import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.messaging.context.MessageContext;

/**
 *  A lookup strategy that returns an instance of {@link HttpServletRequest} supplied at construction time.
 */
public class MockHttpServletRequestLookupStrategy 
        implements ContextDataLookupFunction<MessageContext<?>, HttpServletRequest> {
    
    /** The servlet request. */
    private HttpServletRequest servletRequest;

    /**
     * Constructor.
     *
     * @param request the HttpServletRequest
     */
    public MockHttpServletRequestLookupStrategy(HttpServletRequest request) {
        super();
        servletRequest = Constraint.isNotNull(request, "HttpServletRequest may not be null");
    }

    /** {@inheritDoc} */
    @Nullable public HttpServletRequest apply(@Nullable MessageContext input) {
        return servletRequest;
    }

}
