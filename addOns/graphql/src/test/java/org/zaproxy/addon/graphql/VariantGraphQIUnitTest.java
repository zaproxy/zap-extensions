/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.graphql;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.zaproxy.zap.testutils.TestUtils;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

public class VariantGraphQIUnitTest extends TestUtils{

    @Test
    void shouldNotExtractQueryIfHttpMessageIsNull(){
        //given
        VariantGraphQl vargraphqi=new VariantGraphQl();
        //when
        HttpMessage httpMsg=null;
        //then
        assertThrows(NullPointerException.class,() -> vargraphqi.setMessage(httpMsg));
    }

    @Test
    void shouldNotExtractQueryForPostIfBodyIsEmptyAndNoContentTypeIsSet() throws HttpMalformedHeaderException{
        //given
        VariantGraphQl vargraphqi=new VariantGraphQl();
        //when    
        HttpRequestHeader httpReqHeader=new HttpRequestHeader();
        httpReqHeader.setMessage("POST /abc/xyz HTTP/1.1");
        HttpMessage httpMsg=new HttpMessage(httpReqHeader);
        //then
        assertThrows(NullPointerException.class,() -> vargraphqi.setMessage(httpMsg));
    }
}
