/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.soap.spider;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.spider.parser.ParseContext;
import org.zaproxy.zap.extension.soap.Sample;
import org.zaproxy.zap.extension.soap.WSDLCustomParser;

class WsdlSpiderUnitTest {

    private WSDLCustomParser wsdlCustomParser;
    private ParseContext ctx;
    private WsdlSpider spider;

    @BeforeEach
    void setUp() {
        wsdlCustomParser = mock(WSDLCustomParser.class);
        ctx = mock(ParseContext.class);
        spider = new WsdlSpider(wsdlCustomParser);
    }

    @Test
    void shouldParseWsdl() throws Exception {
        // Given
        HttpMessage message = new HttpMessage();
        Sample.setRequestHeaderContent(message);
        Sample.setResponseHeaderContent(message);
        Sample.setResponseBodyContent(message);
        given(wsdlCustomParser.canBeWSDLparsed(anyString())).willReturn(true);
        given(ctx.getHttpMessage()).willReturn(message);
        // When
        boolean result = spider.parseResource(ctx);
        // Then
        assertTrue(result);
        String content = message.getResponseBody().toString();
        verify(wsdlCustomParser).canBeWSDLparsed(content);
        content = content.trim();
        verify(wsdlCustomParser).extContentWSDLImport(content, true);
    }

    @Test
    void shouldNotParseNonWsdl() throws Exception {
        // Given
        HttpMessage message = new HttpMessage(new URI("https://example.com/", true));
        given(ctx.getHttpMessage()).willReturn(message);
        // When
        boolean result = spider.parseResource(ctx);
        // Then
        assertFalse(result);
        verifyNoInteractions(wsdlCustomParser);
    }

    @Test
    void shouldBeAbleToParseMessageWithWsdlExtension() throws Exception {
        // Given
        HttpMessage message = new HttpMessage(new URI("https://example.com/actions.wsdl", true));
        given(ctx.getHttpMessage()).willReturn(message);
        // When
        boolean result = spider.canParseResource(ctx, false);
        // Then
        assertTrue(result);
    }

    @Test
    void shouldNotBeAbleToParseMessageWithoutWsdlExtension() throws Exception {
        // Given
        HttpMessage message = new HttpMessage(new URI("https://example.com/", true));
        given(ctx.getHttpMessage()).willReturn(message);
        // When
        boolean result = spider.canParseResource(ctx, false);
        // Then
        assertFalse(result);
    }
}
