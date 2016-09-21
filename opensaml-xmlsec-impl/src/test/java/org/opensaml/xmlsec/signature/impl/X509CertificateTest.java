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

package org.opensaml.xmlsec.signature.impl;


import org.testng.annotations.Test;
import org.testng.annotations.BeforeMethod;
import org.testng.Assert;
import org.opensaml.core.xml.XMLObjectProviderBaseTestCase;
import org.opensaml.xmlsec.signature.X509Certificate;

/**
 *
 */
public class X509CertificateTest extends XMLObjectProviderBaseTestCase {
    
    private String expectedStringContent;

    /**
     * Constructor
     *
     */
    public X509CertificateTest() {
        singleElementFile = "/org/opensaml/xmlsec/signature/impl/X509Certificate.xml";
    }

    @BeforeMethod
	protected void setUp() throws Exception {
        expectedStringContent = "someX509Certificate";
    }

    /** {@inheritDoc} */
    @Test
	public void testSingleElementUnmarshall() {
        X509Certificate x509Element = (X509Certificate) unmarshallElement(singleElementFile);
        
        Assert.assertNotNull(x509Element, "X509Certificate");
        Assert.assertEquals(expectedStringContent, x509Element.getValue(), "X509Certificate value");
    }

    /** {@inheritDoc} */
    @Test
	public void testSingleElementMarshall() {
        X509Certificate x509Element = (X509Certificate) buildXMLObject(X509Certificate.DEFAULT_ELEMENT_NAME);
        x509Element.setValue(expectedStringContent);
        
        assertXMLEquals(expectedDOM, x509Element);
    }

}
