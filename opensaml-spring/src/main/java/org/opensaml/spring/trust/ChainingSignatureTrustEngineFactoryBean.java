/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opensaml.spring.trust;

import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.shared.collection.CollectionSupport;
import net.shibboleth.shared.spring.factory.AbstractComponentAwareFactoryBean;

import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ChainingSignatureTrustEngine;

/**
 * Factory bean for {@link ChainingSignatureTrustEngine}. This finesses the issue that some parsers are not supported
 * and return a bean of type object and these cannot be injected into the trust engine. This factory just filters the
 * unsupported engines out. A warning has been issued at point of parse so no further logging is required.
 */
public class ChainingSignatureTrustEngineFactoryBean extends
        AbstractComponentAwareFactoryBean<ChainingSignatureTrustEngine> {

    /** The unfiltered list of putative trust engines. */
    @Nullable private final List<Object> engines;

    /**
     * Constructor.
     * 
     * @param list the putative trust engines.
     */
    public ChainingSignatureTrustEngineFactoryBean(@Nullable final List<Object> list) {
        engines = list;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull public Class<?> getObjectType() {
        return ChainingSignatureTrustEngine.class;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull protected ChainingSignatureTrustEngine doCreateInstance() throws Exception {
        if (engines == null) {
            return new ChainingSignatureTrustEngine(CollectionSupport.emptyList());
        }

        assert engines != null;
        final List<SignatureTrustEngine> list = new ArrayList<>(engines.size());
        assert engines != null;
        for (final Object engine : engines) {
            if (engine instanceof SignatureTrustEngine) {
                list.add((SignatureTrustEngine) engine);
            }
        }
        return new ChainingSignatureTrustEngine(list);
    }

}