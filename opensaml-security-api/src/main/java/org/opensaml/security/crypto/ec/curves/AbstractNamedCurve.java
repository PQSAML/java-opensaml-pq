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

package org.opensaml.security.crypto.ec.curves;

import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.opensaml.security.crypto.JCAConstants;
import org.opensaml.security.crypto.KeySupport;
import org.opensaml.security.crypto.ec.ECSupport;
import org.opensaml.security.crypto.ec.NamedCurve;
import org.slf4j.Logger;

import com.google.common.base.MoreObjects;

import net.shibboleth.shared.annotation.constraint.NonnullAfterInit;
import net.shibboleth.shared.component.AbstractInitializableComponent;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.primitive.LoggerFactory;

/**
 * Abstract base class for implementations of {@link NamedCurve}.
 */
public abstract class AbstractNamedCurve extends AbstractInitializableComponent implements NamedCurve {
    
    /** Logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(this.getClass());
    
    /** Instance of {@link ECParameterSpec} corresponding to the curve. */
    @NonnullAfterInit private ECParameterSpec paramSpec;
    
    /** {@inheritDoc} */
    @Nonnull public ECParameterSpec getParameterSpec() {
        checkComponentActive();
        assert paramSpec != null;
        return paramSpec;
    }

    /** {@inheritDoc} */
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        
        paramSpec = buildParameterSpec();
        
        // This should never happen for any correctly-specified named curve that we'd actually define...
        if (paramSpec == null) {
            throw new ComponentInitializationException("Could not init NamedCurve ECParameterSpec");
        }
    }

    /**
     * Build an instance of {@link ECParameterSpec} corresponding to this curve.
     * 
     * <p>
     * The default implementation here is that it first attempts to resolve the curve from
     * Bouncy Castle's {@link ECNamedCurveTable}.  If that is unsuccessful then it attempts
     * a brute force approach by generating a key pair using a {@link ECGenParameterSpec} based
     * on the curve's name from {@link #getName()}, returning the parameter instance from the
     * resulting {@link ECPublicKey}.
     * </p>
     * 
     * @return the parameter spec instance, or null if can not be built
     */
    @Nullable public ECParameterSpec buildParameterSpec() {
        ECParameterSpec jcaSpec = ECSupport.convert(ECNamedCurveTable.getParameterSpec(getObjectIdentifier()));
        if (jcaSpec != null) {
            log.trace("Inited NamedCurve ECParameterSpec from BC curve table for name '{}', OID '{}'",
                    getName(), getObjectIdentifier());
            return jcaSpec;
        }
        
        log.trace("Failed to init NamedCurve ECParameterSpec from BC named curve table, trying keypair generation");
        
        try {
            jcaSpec = ECPublicKey.class.cast(
                    KeySupport.generateKeyPair(JCAConstants.KEY_ALGO_EC, new ECGenParameterSpec(getName()), null)
                    .getPublic()).getParams();
            log.trace("Inited NamedCurve ECParameterSpec via key pair generation for name '{}', OID '{}'",
                    getName(), getObjectIdentifier());
            return jcaSpec;
        } catch (final Exception e) {
            log.warn("Error initing the NamedCurve ECParameterSpce via key pair generation with name: {}",
                    getName(), e);
        }
        
        log.warn("Failed to init NamedCurve ECParameterSpec from BC or key pair generation for name '{}', OID '{}'",
                getName(), getObjectIdentifier());
        
        return null;
    }

    /** {@inheritDoc} */
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("name", getName())
                .add("OID", getObjectIdentifier())
                .toString();
    }
    
}