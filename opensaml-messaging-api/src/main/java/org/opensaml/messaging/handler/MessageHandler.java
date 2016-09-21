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

package org.opensaml.messaging.handler;

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.component.InitializableComponent;

import org.opensaml.messaging.context.MessageContext;


/**
 *
 *A message handler represents some reusable logic that may be invoked on a message context.
 *
 * @param <MessageType> the type of message being handled
 */
public interface MessageHandler<MessageType> extends InitializableComponent {
    
    /**
     * Invoke the handler on the specified message context.
     * 
     * @param messageContext the message context on which to invoke the handler
     * @throws MessageHandlerException if the there is an error invoking the handler on the message context
     */
    void invoke(@Nonnull final MessageContext<MessageType> messageContext) throws MessageHandlerException;
    
}