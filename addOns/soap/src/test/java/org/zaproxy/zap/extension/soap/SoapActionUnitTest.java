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
package org.zaproxy.zap.extension.soap;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

public class SoapActionUnitTest {

    @ParameterizedTest
    @ValueSource(strings = {"http://example.com/", "", "\"ZAP\""})
    public void getSoapActionForSoapV1Message(String soapAction) {
        HttpMessage soapMsg = new HttpMessage();
        soapMsg.getRequestHeader().setHeader("SOAPAction", soapAction);
        assertThat(SoapAction.extractFrom(soapMsg), is(equalTo(soapAction)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://example.com/", "", "\"ZAP\""})
    public void getSoapActionForSoapV2Message(String soapAction) {
        HttpMessage soapMsg = new HttpMessage();
        String contentType = "application/soap+xml;charset=utf-8;action=" + soapAction;
        soapMsg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, contentType);
        assertThat(SoapAction.extractFrom(soapMsg), is(equalTo(soapAction.replaceAll("\"", ""))));
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://example.com/", "", "\"ZAP\""})
    public void getSoapActionForSoapV2MessageWithActionBeforeCharsetInContentTypeHeader(
            String soapAction) {
        HttpMessage soapMsg = new HttpMessage();
        String contentType = "application/soap+xml;action=" + soapAction + ";charset=utf-8";
        soapMsg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, contentType);
        assertThat(SoapAction.extractFrom(soapMsg), is(equalTo(soapAction.replaceAll("\"", ""))));
    }

    @Test
    public void getSoapActionShouldReturnEmptyStringForSoapV2MessageWithOmittedAction() {
        HttpMessage soapMsg = new HttpMessage();
        String contentType = "application/soap+xml;charset=utf-8";
        soapMsg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, contentType);
        assertThat(SoapAction.extractFrom(soapMsg), is(equalTo("")));
    }

    @Test
    public void getSoapActionShouldReturnNullForInvalidSoapMessage() {
        HttpMessage msg = new HttpMessage();
        msg.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, HttpHeader.JSON_CONTENT_TYPE);
        assertThat(SoapAction.extractFrom(msg), is(nullValue()));
    }
}
