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

package org.opensaml.core.xml.util;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.concurrent.NotThreadSafe;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.collection.LazyMap;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.core.xml.XMLObject;

/**
 * Class which provides storage for the ID-to-XMLObject index mapping on an owning
 * {@link org.opensaml.core.xml.XMLObject}.
 */
@NotThreadSafe
public class IDIndex {
    
    /** The XMLObject which owns this ID index. */
    @Nonnull private final XMLObject owner;
    
    /** Mapping of ID attributes to XMLObjects in the subtree rooted at this object's owner.
     * This allows constant-time dereferencing of ID-typed attributes within the subtree.  */
    @Nonnull private Map<String, XMLObject> idMappings;

    /**
     * Constructor.
     *
     * @param newOwner the XMLObject which owns this ID-to-XMLObject index
     */
    public IDIndex(@Nonnull final XMLObject newOwner) {
        Constraint.isNotNull(newOwner, "ID-owning XMLObject may not be null");
        
        owner = newOwner;
        idMappings = new LazyMap<>();
    }
    

    /**
     * Register an ID-to-XMLObject mapping for one of this object's owner's children.
     * 
     * @param id the XMLObject child's ID attribute value
     * @param referent the XMLObject child
     */
    public void registerIDMapping(@Nonnull @NotEmpty final String id, @Nonnull final XMLObject referent) {
        if (id == null) {
            return;
        }
        
        idMappings.put(id, referent);
        if (owner.hasParent()) {
            owner.getParent().getIDIndex().registerIDMapping(id, referent);
        }
    }
    
    /**
     * Register multiple ID-to-XMLObject mappings for this object's owner's children.
     * 
     * @param idIndex the ID-to-XMLObject mapping to register
     */
    public void registerIDMappings(@Nonnull final IDIndex idIndex) {
        if (idIndex == null || idIndex.isEmpty()) {
            return;
        }
        
        idMappings.putAll(idIndex.getIDMappings());
        if (owner.hasParent()) {
            owner.getParent().getIDIndex().registerIDMappings(idIndex);
        }
    }
    
    /**
     * Deregister an ID-to-XMLObject mapping for one of this object's owner's children.
     * 
     * @param id the ID attribute value of the XMLObject child to deregister
     */  
    public void deregisterIDMapping(@Nonnull @NotEmpty final String id) {
        if (id == null) {
            return;
        }
        
        idMappings.remove(id);
        if (owner.hasParent()) {
            owner.getParent().getIDIndex().deregisterIDMapping(id);
        }
    }
    
    /**
     * Deregister multiple ID-to-XMLObject mappings for this object's owner's children.
     * 
     * @param idIndex the ID-to-XMLObject mappings to deregister
     */
    public void deregisterIDMappings(@Nonnull final IDIndex idIndex) {
        if (idIndex == null || idIndex.isEmpty()) {
            return;
        }
        
        for (String id : idIndex.getIDs()) {
            idMappings.remove(id);
        }
        if (owner.hasParent()) {
            owner.getParent().getIDIndex().deregisterIDMappings(idIndex);
        }
    }
 
    /**
     * Lookup and return the XMLObject identified by the specified ID attribute.
     * 
     * @param id the ID attribute value to lookup
     * @return the XMLObject identified by the ID attribute value
     */
    @Nullable public XMLObject lookup(@Nonnull @NotEmpty final String id) {
        return idMappings.get(id);
    }
    
    /**
     * Return whether the index is currently empty.
     * 
     * @return true if the index is currently empty
     */
    public boolean isEmpty() {
        return idMappings.isEmpty();
    }
    
    /**
     * Get the set of ID strings which are the index keys.
     * 
     * @return the set of ID strings which are keys to the index
     */
    @Nonnull public Set<String> getIDs() {
        return Collections.unmodifiableSet(idMappings.keySet());
    }
    
    /**
     * Get the ID-to-XMLObject mappings for this object's owner's children.
     * 
     * @return the ID-to-XMLObject mapping
     */
    @Nonnull protected Map<String, XMLObject> getIDMappings() {
        return Collections.unmodifiableMap(idMappings);
    }
    
}
