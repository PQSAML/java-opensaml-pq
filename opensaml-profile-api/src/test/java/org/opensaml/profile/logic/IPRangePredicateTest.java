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

package org.opensaml.profile.logic;

import java.util.Map;

import net.shibboleth.ext.spring.config.IdentifiableBeanPostProcessor;
import net.shibboleth.ext.spring.util.ApplicationContextBuilder;

import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Unit test of {@link IPRangePredicate}.
 */
public class IPRangePredicateTest {

    @Test public void testRanges() {

        final GenericApplicationContext ctx = new ApplicationContextBuilder()
               .setName("IpRange")
               .setServiceConfiguration(new ClassPathResource("iprange.xml"))
               .setBeanPostProcessor(new IdentifiableBeanPostProcessor())
               .build();

        final Map<String,IPRangePredicate> map = ctx.getBeansOfType(IPRangePredicate.class);
        Assert.assertEquals(map.size(), 2);

        final MockHttpServletRequest request = new MockHttpServletRequest();
   
        IPRangePredicate condition = map.get("three");
        condition.setHttpServletRequest(request);
   
        request.setRemoteAddr("192.168.1.128");
        Assert.assertTrue(condition.test(null));

        request.setRemoteAddr("192.168.3.128");
        Assert.assertFalse(condition.test(null));

        request.setRemoteAddr("::1");
        Assert.assertFalse(condition.test(null));

        condition = map.get("four");
        condition.setHttpServletRequest(request);

        request.setRemoteAddr("2620:df:8000:ff14:0:0:0:2");
        Assert.assertTrue(condition.test(null));
        
        request.setRemoteAddr("2620:df:8000:ff14:0:0:0:3");
        Assert.assertFalse(condition.test(null));
        
        request.setRemoteAddr("[2620:df:8000:ff14:0:0:0:2]");
        Assert.assertTrue(condition.test(null));
    }

}