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
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

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

/**
 * SAML 2.0 HTTP Redirect decoder using the DEFLATE encoding method.
 * 
 * This decoder only supports DEFLATE compression.
 */
public class HTTPRedirectDeflateDecoder extends BaseHttpServletRequestXMLMessageDecoder<SAMLObject> 
    implements SAMLMessageDecoder {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(HTTPRedirectDeflateDecoder.class);

    /** Optional {@link BindingDescriptor} to inject into {@link SAMLBindingContext} created. */
    @Nullable private BindingDescriptor bindingDescriptor;
    
    /** {@inheritDoc} */
    @Nonnull @NotEmpty public String getBindingURI() {
        return SAMLConstants.SAML2_REDIRECT_BINDING_URI;
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
        MessageContext<SAMLObject> messageContext = new MessageContext<>();
        HttpServletRequest request = getHttpServletRequest();
        
        if (!"GET".equalsIgnoreCase(request.getMethod())) {
            throw new MessageDecodingException("This message decoder only supports the HTTP GET method");
        }
        
        String samlEncoding = StringSupport.trimOrNull(request.getParameter("SAMLEncoding"));
        if (samlEncoding != null && !SAMLConstants.SAML2_BINDING_URL_ENCODING_DEFLATE_URI.equals(samlEncoding)) {
            throw new MessageDecodingException("Request indicated an unsupported SAMLEncoding: " + samlEncoding);
        }

        String relayState = request.getParameter("RelayState");
        log.debug("Decoded RelayState: {}", relayState);
        SAMLBindingSupport.setRelayState(messageContext, relayState);

        InputStream samlMessageIns;
        if (!Strings.isNullOrEmpty(request.getParameter("SAMLRequest"))) {
            samlMessageIns = decodeMessage(request.getParameter("SAMLRequest"));
        } else if (!Strings.isNullOrEmpty(request.getParameter("SAMLResponse"))) {
            samlMessageIns = decodeMessage(request.getParameter("SAMLResponse"));
        } else {
            throw new MessageDecodingException(
                    "No SAMLRequest or SAMLResponse query path parameter, invalid SAML 2 HTTP Redirect message");
        }

        SAMLObject samlMessage = (SAMLObject) unmarshallMessage(samlMessageIns);
        messageContext.setMessage(samlMessage);
        log.debug("Decoded SAML message");

        populateBindingContext(messageContext);
        
        setMessageContext(messageContext);
    }

    /**
     * Base64 decodes the SAML message and then decompresses the message.
     * 
     * @param message Base64 encoded, DEFALTE compressed, SAML message
     * 
     * @return the SAML message
     * 
     * @throws MessageDecodingException thrown if the message can not be decoded
     */
    protected InputStream decodeMessage(String message) throws MessageDecodingException {
        log.debug("Base64 decoding and inflating SAML message");

        byte[] decodedBytes = Base64Support.decode(message);
        if(decodedBytes == null){
            log.error("Unable to Base64 decode incoming message");
            throw new MessageDecodingException("Unable to Base64 decode incoming message");
        }
        
        try {
            ByteArrayInputStream bytesIn = new ByteArrayInputStream(decodedBytes);
            InflaterInputStream inflater = new InflaterInputStream(bytesIn, new Inflater(true));
            return inflater;
        } catch (Exception e) {
            log.error("Unable to Base64 decode and inflate SAML message", e);
            throw new MessageDecodingException("Unable to Base64 decode and inflate SAML message", e);
        }
    }
    
    /**
     * Populate the context which carries information specific to this binding.
     * 
     * @param messageContext the current message context
     */
    protected void populateBindingContext(MessageContext<SAMLObject> messageContext) {
        SAMLBindingContext bindingContext = messageContext.getSubcontext(SAMLBindingContext.class, true);
        bindingContext.setBindingUri(getBindingURI());
        bindingContext.setBindingDescriptor(bindingDescriptor);
        bindingContext.setHasBindingSignature(
                !Strings.isNullOrEmpty(getHttpServletRequest().getParameter("Signature")));
        bindingContext.setIntendedDestinationEndpointURIRequired(SAMLBindingSupport.isMessageSigned(messageContext));
    }
    
}