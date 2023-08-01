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

package org.opensaml.soap.testing;

import org.testng.annotations.Test;
import org.testng.annotations.BeforeMethod;
import org.testng.Assert;
import javax.xml.namespace.QName;

import org.opensaml.core.testing.XMLObjectBaseTestCase;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.soap.soap11.Body;
import org.opensaml.soap.soap11.Detail;
import org.opensaml.soap.soap11.Envelope;
import org.opensaml.soap.soap11.Fault;
import org.opensaml.soap.soap11.FaultActor;
import org.opensaml.soap.soap11.FaultCode;
import org.opensaml.soap.soap11.FaultString;
import org.opensaml.soap.soap11.Header;
import org.opensaml.soap.util.SOAPConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.google.common.base.Strings;

import net.shibboleth.shared.xml.XMLParserException;

/**
 * Tests marshalling and unmarshalling SOAP messages.
 */
public class SOAPTest extends XMLObjectBaseTestCase {
    
    /** Path, on classpath, to SOAP message test document. */
    private String soapMessage;
    
    /** Path, on classpath, to SOAP fault test document. */
    private String soapFault;
    
    /** Path, on classpath, to SOAP fault test document. */
    private String soapFaultMarshall;
    
    private QName expectedFaultCode;
    
    private String expectedFaultString;
    
    private String expectedFaultActor;

    @BeforeMethod
    protected void setUp() throws Exception {
        soapMessage = "/org/opensaml/soap/soap11/SOAP.xml";
        soapFault = "/org/opensaml/soap/soap11/SOAPFault.xml";
        soapFaultMarshall = "/org/opensaml/soap/soap11/SOAPFaultMarshall.xml";
        
        expectedFaultCode = new QName(SOAPConstants.SOAP11_NS, "Server", SOAPConstants.SOAP11_PREFIX);
        expectedFaultString = "Server Error";
        expectedFaultActor = "http://ws.example.org/someActor";
    }
    
    /**
     * Test unmarshalling a SOAP message, dropping its DOM representation and then remarshalling it.
     * 
     * @throws XMLParserException thrown if the XML document can not be located or parsed into a DOM 
     * @throws UnmarshallingException thrown if the DOM can not be unmarshalled
     */
    @Test
    public void testSOAPMessage() throws XMLParserException, UnmarshallingException{
        final Document soapDoc = parserPool.parse(SOAPTest.class.getResourceAsStream(soapMessage));
        final Element envelopeElem = soapDoc.getDocumentElement();
        final Unmarshaller unmarshaller = unmarshallerFactory.ensureUnmarshaller(envelopeElem);
        
        final Envelope envelope = (Envelope) unmarshaller.unmarshall(envelopeElem);
        
        // Check to make sure everything unmarshalled okay
        final QName encodingStyleName = new QName("http://schemas.xmlsoap.org/soap/envelope/", "encodingStyle");
        String encodingStyleValue = envelope.getUnknownAttributes().get(encodingStyleName);
        Assert.assertNotNull(encodingStyleValue, "Encoding style was null");
        Assert.assertEquals(encodingStyleValue, 
                "http://schemas.xmlsoap.org/soap/encoding/", "Encoding style had unexpected value");
        
        final Header header = envelope.getHeader();
        assert header != null;
        Assert.assertEquals(header.getUnknownXMLObjects().size(), 1, "Unexpected number of Header children");
        
        final Body body = envelope.getBody();
        assert body != null;
        Assert.assertEquals(body.getUnknownXMLObjects().size(), 1, "Unexpected number of Body children");
        
        // Drop the DOM and remarshall, hopefully we get the same document back
        envelope.releaseDOM();
        envelope.releaseChildrenDOM(true);
        assertXMLEquals("Marshalled DOM was not the same as control DOM", soapDoc, envelope);
    }
    
    /**
     * Test unmarshalling a SOAP fault, dropping its DOM representation and then remarshalling it.
     * @throws XMLParserException thrown if the XML document can not be located or parsed into a DOM 
     * @throws UnmarshallingException thrown if the DOM can not be unmarshalled
     */
    @Test
    public void testSOAPFault() throws XMLParserException, UnmarshallingException{
        final Document soapFaultDoc = parserPool.parse(SOAPTest.class.getResourceAsStream(soapFault));
        final Element envelopeElem = soapFaultDoc.getDocumentElement();
        final Unmarshaller unmarshaller = unmarshallerFactory.ensureUnmarshaller(envelopeElem);
        
        final Envelope envelope = (Envelope) unmarshaller.unmarshall(envelopeElem);
        
        // Check to make sure everything unmarshalled okay
        final Header header = envelope.getHeader();
        Assert.assertNull(header, "Header was not null");
        
        final Body body = envelope.getBody();
        assert body != null;
        Assert.assertEquals(body.getUnknownXMLObjects().size(), 1, "Unexpected number of Body children");
        
        final Fault fault = (Fault) body.getUnknownXMLObjects().get(0);
        assert fault != null;
        
        final FaultActor actor = fault.getActor();
        assert actor != null;
        Assert.assertEquals(actor.getURI(), expectedFaultActor, "FaultActor had unexpected value");
        
        final FaultCode code = fault.getCode();
        assert code != null;
        Assert.assertEquals(code.getValue(), expectedFaultCode, "FaultCode had unexpected value");
        
        final FaultString message = fault.getMessage();
        assert message != null;
        Assert.assertEquals(message.getValue(), expectedFaultString, "FaultString had unexpected value");
        
        final Detail detail = fault.getDetail();
        assert detail != null;
        Assert.assertEquals(detail.getUnknownXMLObjects().size(), 1, "Unexpected number of Body children");
        
        // Drop the DOM and remarshall, hopefully we get the same document back
        envelope.releaseDOM();
        envelope.releaseChildrenDOM(true);
        assertXMLEquals("Marshalled DOM was not the same as control DOM", soapFaultDoc, envelope);
    }
    
    /**
     * Test constructing and marshalling a SOAP fault message.
     * 
     * @throws MarshallingException  if the DOM can not b marshalled
     * @throws XMLParserException ...
     */
    @Test
    public void testSOAPFaultConstructAndMarshall() throws MarshallingException, XMLParserException {
        Document soapDoc = parserPool.parse(SOAPTest.class.getResourceAsStream(soapFaultMarshall));
        
        Envelope envelope = (Envelope) buildXMLObject(Envelope.DEFAULT_ELEMENT_NAME);
        
        Body body = (Body) buildXMLObject(Body.DEFAULT_ELEMENT_NAME);
        envelope.setBody(body);
        
        Fault fault = (Fault) buildXMLObject(Fault.DEFAULT_ELEMENT_NAME);
        body.getUnknownXMLObjects().add(fault);
        
        FaultCode faultCode = (FaultCode) buildXMLObject(FaultCode.DEFAULT_ELEMENT_NAME);
        faultCode.setValue(expectedFaultCode);
        fault.setCode(faultCode);
        
        FaultString faultString = (FaultString) buildXMLObject(FaultString.DEFAULT_ELEMENT_NAME);
        faultString.setValue(expectedFaultString);
        fault.setMessage(faultString);
        
        FaultActor faultActor = (FaultActor) buildXMLObject(FaultActor.DEFAULT_ELEMENT_NAME);
        faultActor.setURI(expectedFaultActor);
        fault.setActor(faultActor);
        
        Detail detail = (Detail) buildXMLObject(Detail.DEFAULT_ELEMENT_NAME);
        fault.setDetail(detail);
        
        marshallerFactory.ensureMarshaller(envelope).marshall(envelope);
        assertXMLEquals("Marshalled DOM was not the same as control DOM", soapDoc, envelope);
        
    }
    
    /**
     *  Test that the no-arg SOAP fault-related builders are operating correcting, i.e. not namespace-qualified.
     */
    @Test
    public void testSOAPFaultBuilders() {
       
       XMLObjectBuilder<Detail> detailBuilder = builderFactory.ensureBuilder(Detail.DEFAULT_ELEMENT_NAME); 
       Detail detail = detailBuilder.buildObject(Detail.DEFAULT_ELEMENT_NAME);
       Assert.assertTrue(Strings.isNullOrEmpty(detail.getElementQName().getNamespaceURI()), "Namespace URI was not empty");
       Assert.assertTrue(Strings.isNullOrEmpty(detail.getElementQName().getPrefix()), "Namespace prefix was not empty");
        
       XMLObjectBuilder<FaultActor> faultActorBuilder = builderFactory.ensureBuilder(FaultActor.DEFAULT_ELEMENT_NAME); 
       FaultActor faultActor = faultActorBuilder.buildObject(FaultActor.DEFAULT_ELEMENT_NAME);
       Assert.assertTrue(Strings.isNullOrEmpty(faultActor.getElementQName().getNamespaceURI()), "Namespace URI was not empty");
       Assert.assertTrue(Strings.isNullOrEmpty(faultActor.getElementQName().getPrefix()), "Namespace prefix was not empty");
       
       XMLObjectBuilder<FaultCode> faultCodeBuilder = builderFactory.ensureBuilder(FaultCode.DEFAULT_ELEMENT_NAME); 
       FaultCode faultCode = faultCodeBuilder.buildObject(FaultCode.DEFAULT_ELEMENT_NAME);
       Assert.assertTrue(Strings.isNullOrEmpty(faultCode.getElementQName().getNamespaceURI()), "Namespace URI was not empty");
       Assert.assertTrue(Strings.isNullOrEmpty(faultCode.getElementQName().getPrefix()), "Namespace prefix was not empty");
       
       XMLObjectBuilder<FaultString> faultStringBuilder = builderFactory.ensureBuilder(FaultString.DEFAULT_ELEMENT_NAME); 
       FaultString faultString = faultStringBuilder.buildObject(FaultString.DEFAULT_ELEMENT_NAME);
       Assert.assertTrue(Strings.isNullOrEmpty(faultString.getElementQName().getNamespaceURI()), "Namespace URI was not empty");
       Assert.assertTrue(Strings.isNullOrEmpty(faultString.getElementQName().getPrefix()), "Namespace prefix was not empty");
    }
}