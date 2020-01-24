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

package org.opensaml.saml.saml2.binding.decoding.impl;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.codec.DecodingException;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.decoder.servlet.BaseHttpServletRequestXMLMessageDecoder;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.BindingDescriptor;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;

/** Message decoder implementing the SAML 2.0 HTTP POST binding. */
public class HTTPPostDecoder extends BaseHttpServletRequestXMLMessageDecoder implements SAMLMessageDecoder {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(HTTPPostDecoder.class);

    /** Optional {@link BindingDescriptor} to inject into {@link SAMLBindingContext} created. */
    @Nullable private BindingDescriptor bindingDescriptor;
    
    /** {@inheritDoc} */
    @Nonnull @NotEmpty public String getBindingURI() {
        return SAMLConstants.SAML2_POST_BINDING_URI;
    }
    
    /**
     * Get an optional {@link BindingDescriptor} to inject into {@link SAMLBindingContext} created.
     * 
     * @return binding descriptor
     */
    @Nullable public BindingDescriptor getBindingDescriptor() {
        return bindingDescriptor;
    }
    
    /**
     * Set an optional {@link BindingDescriptor} to inject into {@link SAMLBindingContext} created.
     * 
     * @param descriptor a binding descriptor
     */
    public void setBindingDescriptor(@Nullable final BindingDescriptor descriptor) {
        bindingDescriptor = descriptor;
    }

    /** {@inheritDoc} */
    protected void doDecode() throws MessageDecodingException {
        final MessageContext messageContext = new MessageContext();
        final HttpServletRequest request = getHttpServletRequest();

        if (!"POST".equalsIgnoreCase(request.getMethod())) {
            throw new MessageDecodingException("This message decoder only supports the HTTP POST method");
        }

        final String relayState = request.getParameter("RelayState");
        log.debug("Decoded SAML relay state of: {}", relayState);
        SAMLBindingSupport.setRelayState(messageContext, relayState);

        final InputStream base64DecodedMessage = getBase64DecodedMessage(request);
        final SAMLObject inboundMessage = (SAMLObject) unmarshallMessage(base64DecodedMessage);
        messageContext.setMessage(inboundMessage);
        log.debug("Decoded SAML message");

        populateBindingContext(messageContext);
        
        setMessageContext(messageContext);
    }

    /**
     * Gets the Base64 encoded message from the request and decodes it.
     * 
     * @param request the inbound HTTP servlet request
     * 
     * @return decoded message
     * 
     * @throws MessageDecodingException thrown if the message does not contain a base64 encoded SAML message, 
     *                                      or the message can not be base64-decoded.
     */
    protected InputStream getBase64DecodedMessage(final HttpServletRequest request) throws MessageDecodingException {
        log.debug("Getting Base64 encoded message from request");
        String encodedMessage = request.getParameter("SAMLRequest");
        if (Strings.isNullOrEmpty(encodedMessage)) {
            encodedMessage = request.getParameter("SAMLResponse");
        }

        if (Strings.isNullOrEmpty(encodedMessage)) {
            log.error("Request did not contain either a SAMLRequest or "
                    + "SAMLResponse paramter.  Invalid request for SAML 2 HTTP POST binding.");
            throw new MessageDecodingException("No SAML message present in request");
        }

        try {
            log.trace("Base64 decoding SAML message:\n{}", encodedMessage);
            final byte[] decodedBytes = Base64Support.decode(encodedMessage);            
            log.trace("Decoded SAML message:\n{}", new String(decodedBytes));
            return new ByteArrayInputStream(decodedBytes);
            
        } catch (final DecodingException e) {        
            log.error("Unable to Base64 decode SAML message");
            throw new MessageDecodingException("Unable to Base64 decode SAML message",e);
        }      
    }
    
    /**
     * Populate the context which carries information specific to this binding.
     * 
     * @param messageContext the current message context
     */
    protected void populateBindingContext(final MessageContext messageContext) {
        final SAMLBindingContext bindingContext = messageContext.getSubcontext(SAMLBindingContext.class, true);
        bindingContext.setBindingUri(getBindingURI());
        bindingContext.setBindingDescriptor(bindingDescriptor);
        bindingContext.setHasBindingSignature(false);
        bindingContext.setIntendedDestinationEndpointURIRequired(SAMLBindingSupport.isMessageSigned(messageContext));
    }
    
}