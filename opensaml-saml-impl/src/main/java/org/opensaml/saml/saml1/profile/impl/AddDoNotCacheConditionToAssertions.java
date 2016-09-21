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

package org.opensaml.saml.saml1.profile.impl;

import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.messaging.context.navigate.MessageLookup;
import org.opensaml.profile.action.AbstractConditionalProfileAction;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.OutboundMessageContextLookup;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.saml1.core.Assertion;
import org.opensaml.saml.saml1.core.Conditions;
import org.opensaml.saml.saml1.core.DoNotCacheCondition;
import org.opensaml.saml.saml1.core.Response;
import org.opensaml.saml.saml1.profile.SAML1ActionSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;

/**
 * Action to add a {@link DoNotCacheCondition} to every {@link Assertion} in a {@link Response} message.
 * If the containing {@link Conditions} is not present, it will be created.
 * 
 * @event {@link EventIds#PROCEED_EVENT_ID}
 * @event {@link EventIds#INVALID_MSG_CTX}
 */
public class AddDoNotCacheConditionToAssertions extends AbstractConditionalProfileAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(AddDoNotCacheConditionToAssertions.class);

    /** Strategy used to locate the {@link Response} to operate on. */
    @Nonnull private Function<ProfileRequestContext,Response> responseLookupStrategy;

    /** Response to modify. */
    @Nullable private Response response;

    /** Constructor. */
    public AddDoNotCacheConditionToAssertions() {
        responseLookupStrategy =
                Functions.compose(new MessageLookup<>(Response.class), new OutboundMessageContextLookup());
    }
    
    /**
     * Set the strategy used to locate the {@link Response} to operate on.
     * 
     * @param strategy strategy used to locate the {@link Response} to operate on
     */
    public void setResponseLookupStrategy(@Nonnull final Function<ProfileRequestContext, Response> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        responseLookupStrategy = Constraint.isNotNull(strategy, "Response lookup strategy cannot be null");
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext) {
        log.debug("{} Attempting to add DoNotCache condition to every Assertion in Response", getLogPrefix());

        response = responseLookupStrategy.apply(profileRequestContext);
        if (response == null) {
            log.debug("{} No SAML response located in current profile request context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_MSG_CTX);
            return false;
        } else if (response.getAssertions().isEmpty()) {
            log.debug("{} No assertions in response message, nothing to do", getLogPrefix());
            return false;
        }
        
        return super.doPreExecute(profileRequestContext);
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext) {

        final SAMLObjectBuilder<DoNotCacheCondition> dncConditionBuilder = (SAMLObjectBuilder<DoNotCacheCondition>)
                XMLObjectProviderRegistrySupport.getBuilderFactory().<DoNotCacheCondition>getBuilderOrThrow(
                        DoNotCacheCondition.DEFAULT_ELEMENT_NAME);

        for (final Assertion assertion : response.getAssertions()) {
            final Conditions conditions = SAML1ActionSupport.addConditionsToAssertion(this, assertion);
            final List<DoNotCacheCondition> dncConditions = conditions.getDoNotCacheConditions();
            if (dncConditions.isEmpty()) {
                dncConditions.add(dncConditionBuilder.buildObject());
                log.debug("{} Added DoNotCache condition to Assertion {}", getLogPrefix(), assertion.getID());
            } else {
                log.debug("{} Assertion {} already contained DoNotCache condition, another was not added",
                        getLogPrefix(), assertion.getID());
            }

        }
    }

}