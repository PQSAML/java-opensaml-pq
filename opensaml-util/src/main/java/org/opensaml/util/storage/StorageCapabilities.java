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

package org.opensaml.util.storage;

import javax.annotation.Nonnull;

import com.google.common.base.Optional;

/**
 * Exposes capabilities of a {@link StorageService} implementation.
 */
public interface StorageCapabilities {
    
    /**
     * Gets max size of context labels in characters.
     * 
     * @return  max size of context labels in characters, if any
     */
    @Nonnull public Optional<Integer> getContextSize();

    /**
     * Gets max size of keys in characters.
     * 
     * @return  max size of keys in characters, if any
     */
    @Nonnull public Optional<Integer> getKeySize();

    /**
     * Gets max size of string values in characters.
     * 
     * @return  max size of string values in characters, if any
     */
    @Nonnull public Optional<Integer> getStringSize();
    
    /**
     * Gets max size of text values in characters.
     * 
     * @return  max size of text values in characters, if any
     */
    @Nonnull public Optional<Long> getTextSize();

}