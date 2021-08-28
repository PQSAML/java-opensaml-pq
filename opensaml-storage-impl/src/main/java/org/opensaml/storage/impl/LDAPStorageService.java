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

package org.opensaml.storage.impl;

import java.io.IOException;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.annotation.constraint.Positive;
import net.shibboleth.utilities.java.support.collection.Pair;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.ldaptive.AttributeModification;
import org.ldaptive.Connection;
import org.ldaptive.DeleteOperation;
import org.ldaptive.DeleteRequest;
import org.ldaptive.DeleteResponse;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.ModifyOperation;
import org.ldaptive.ModifyRequest;
import org.ldaptive.ModifyResponse;
import org.ldaptive.PooledConnectionFactory;
import org.ldaptive.Result;
import org.ldaptive.ResultCode;
import org.ldaptive.SearchOperation;
import org.ldaptive.SearchRequest;
import org.ldaptive.SearchResponse;
import org.ldaptive.ext.MergeOperation;
import org.ldaptive.ext.MergeRequest;
import org.opensaml.storage.AbstractStorageService;
import org.opensaml.storage.StorageCapabilitiesEx;
import org.opensaml.storage.StorageRecord;
import org.opensaml.storage.VersionMismatchException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of {@link org.opensaml.storage.StorageService} that stores data in an LDAP. Does not support
 * expiration or versioning at this time.
 */
public class LDAPStorageService extends AbstractStorageService implements StorageCapabilitiesEx {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(LDAPStorageService.class);

    /** LDAP connection factory. */
    private PooledConnectionFactory connectionFactory;

    /** Attributes to include in merge operations. */
    private LdapAttribute[] defaultAttributes;

    /**
     * Creates a new LDAP storage service.
     * 
     * @param factory to retrieve LDAP connections from
     * @param attrs to include in all LDAP entries
     */
    public LDAPStorageService(@Nonnull final PooledConnectionFactory factory, final LdapAttribute... attrs) {
        connectionFactory = Constraint.isNotNull(factory, "ConnectionFactory cannot be null");
        defaultAttributes = attrs;

        setContextSize(Integer.MAX_VALUE);
        setKeySize(Integer.MAX_VALUE);
        setValueSize(Integer.MAX_VALUE);
    }
    
    /** {@inheritDoc} */
    public boolean isServerSide() {
        return true;
    }

    /** {@inheritDoc} */
    public boolean isClustered() {
        return true;
    }

    /** {@inheritDoc} */
    @Override protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        connectionFactory.initialize();
    }

    /** {@inheritDoc} */
    @Override protected void doDestroy() {
        super.doDestroy();
        if (isInitialized()) {
            connectionFactory.close();
            connectionFactory = null;
        }
    }

    /** {@inheritDoc} */
    @Override public boolean create(@Nonnull @NotEmpty final String context, @Nonnull @NotEmpty final String key,
            @Nonnull @NotEmpty final String value, @Nullable @Positive final Long expiration) throws IOException {
        if (expiration != null) {
            throw new UnsupportedOperationException("Expiration not supported");
        }
        final LdapEntry entry = LdapEntry.builder().dn(context).attributes(defaultAttributes).build();
        entry.addAttributes(new LdapAttribute(key, value));
        try {
            merge(entry);
            return true;
        } catch (final LdapException e) {
            log.error("LDAP merge operation failed: {}", e.getMessage());
            throw new IOException(e);
        }
    }

    /** {@inheritDoc} */
    @Override @Nullable public <T> StorageRecord<T> read(@Nonnull @NotEmpty final String context,
            @Nonnull @NotEmpty final String key) throws IOException {
        SearchResponse result = null;
        try {
            result = search(context, key);
        } catch (final LdapException e) {
            if (e.getResultCode() != ResultCode.NO_SUCH_OBJECT) {
                log.error("LDAP search operation failed: {}", e.getMessage());
                throw new IOException(e);
            }
        }
        StorageRecord<T> record = null;
        if (result != null && result.entrySize() > 0) {
            final LdapEntry entry = result.getEntry();
            if (entry != null) {
                final LdapAttribute attr = entry.getAttribute(key);
                if (attr != null) {
                    record = new StorageRecord<>(attr.getStringValue(), null);
                }
            }
        }
        return record;
    }

    /** {@inheritDoc} */
    @Override @Nonnull public <T> Pair<Long,StorageRecord<T>> read(@Nonnull @NotEmpty final String context,
            @Nonnull @NotEmpty final String key, @Positive final long version) throws IOException {
        throw new UnsupportedOperationException("Versioning not supported");
    }

    /** {@inheritDoc} */
    @Override public boolean update(@Nonnull @NotEmpty final String context, @Nonnull @NotEmpty final String key,
            @Nonnull @NotEmpty final String value, @Nullable @Positive final Long expiration) throws IOException {
        if (expiration != null) {
            throw new UnsupportedOperationException("Expiration not supported");
        }
        final LdapEntry entry = LdapEntry.builder().dn(context).attributes(defaultAttributes).build();
        entry.addAttributes(new LdapAttribute(key, value));
        try {
            merge(entry);
            return true;
        } catch (final LdapException e) {
            log.error("LDAP merge operation failed: {}", e.getMessage());
            throw new IOException(e);
        }
    }

    /** {@inheritDoc} */
    @Override @Nullable public Long updateWithVersion(@Positive final long version,
            @Nonnull @NotEmpty final String context, @Nonnull @NotEmpty final String key,
            @Nonnull @NotEmpty final String value, @Nullable @Positive final Long expiration) throws IOException,
            VersionMismatchException {
        throw new UnsupportedOperationException("Versioning not supported");
    }

    /** {@inheritDoc} */
    @Override public boolean updateExpiration(@Nonnull @NotEmpty final String context,
            @Nonnull @NotEmpty final String key, @Nullable @Positive final Long expiration) throws IOException {
        throw new UnsupportedOperationException("Expiration not supported");
    }

    /** {@inheritDoc} */
    @Override public boolean delete(@Nonnull @NotEmpty final String context, @Nonnull @NotEmpty final String key)
            throws IOException {
        try {
            deleteAttribute(context, key);
            return true;
        } catch (final LdapException e) {
            log.error("LDAP modify operation failed: {}", e.getMessage());
            throw new IOException(e);
        }
    }

    /** {@inheritDoc} */
    @Override public boolean deleteWithVersion(@Positive final long version, @Nonnull @NotEmpty final String context,
            @Nonnull @NotEmpty final String key) throws IOException, VersionMismatchException {
        throw new UnsupportedOperationException("Versioning not supported");
    }

    /** {@inheritDoc} */
    @Override public void reap(@Nonnull @NotEmpty final String context) throws IOException {
        // no-op, expiration not supported
    }

    /** {@inheritDoc} */
    @Override public void updateContextExpiration(@Nonnull @NotEmpty final String context,
            @Nullable @Positive final Long expiration) throws IOException {
        throw new UnsupportedOperationException("Expiration not supported");
    }

    /** {@inheritDoc} */
    @Override public void deleteContext(@Nonnull @NotEmpty final String context) throws IOException {
        try {
            delete(context);
        } catch (final LdapException e) {
            log.error("LDAP delete operation failed", e);
            throw new IOException(e);
        }
    }

    /**
     * Executes a {@link MergeOperation} with the supplied entry.
     * 
     * @param entry to merge
     * 
     * @return response for the merge operation
     * 
     * @throws LdapException if the operation fails
     */
    @Nonnull private Result merge(@Nonnull final LdapEntry entry) throws LdapException {
        final MergeOperation merge = new MergeOperation(connectionFactory);
        final MergeRequest request = new MergeRequest(entry);
        request.setIncludeAttributes(entry.getAttributeNames());
        return merge.execute(request);
    }

    /**
     * Executes a object level {@link SearchOperation} on the supplied DN, returning the supplied attributes.
     * 
     * @param dn to search on
     * @param attrs to return
     * 
     * @return response for the search operation
     * 
     * @throws LdapException if the operation fails
     */
    @Nonnull private SearchResponse search(@Nonnull final String dn, final String... attrs)
            throws LdapException {
        final SearchOperation search = new SearchOperation(connectionFactory);
        return search.execute(SearchRequest.objectScopeSearchRequest(dn, attrs));
    }

    /**
     * Executes a {@link ModifyOperation} on the supplied DN, removing the supplied attribute.
     * 
     * @param dn to modify
     * @param attrName to remove
     * 
     * @return response for the modify operation
     * 
     * @throws LdapException if the operation fails
     */
    @Nonnull private ModifyResponse deleteAttribute(@Nonnull final String dn, @Nonnull final String attrName)
            throws LdapException {
        final ModifyOperation modify = new ModifyOperation(connectionFactory);
        return modify.execute(new ModifyRequest(dn, new AttributeModification(AttributeModification.Type.DELETE,
            new LdapAttribute(attrName))));
    }

    /**
     * Executes a {@link DeleteOperation} on the supplied DN.
     * 
     * @param dn to delete
     * 
     * @return response for the delete operation
     * 
     * @throws LdapException if the operation fails
     */
    @Nonnull private DeleteResponse delete(@Nonnull final String dn) throws LdapException {
        final DeleteOperation delete = new DeleteOperation(connectionFactory);
        return delete.execute(new DeleteRequest(dn));
    }
}