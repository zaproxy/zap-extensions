/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesBeta;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

public class XBackendServerInformationLeakScanRuleUnitTest
        extends PassiveScannerTest<XBackendServerInformationLeakScanRule> {

    private static final String XBS_HEADER = "X-Backend-Server";
    private static final String HEADER_VALUE = "developer1.webapp.scl3.mozilla.com";

    private HttpMessage createMessage() throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        return msg;
    }

    @Override
    protected XBackendServerInformationLeakScanRule createScanner() {
        return new XBackendServerInformationLeakScanRule();
    }

    @Test
    public void shouldNotRaiseAlertIfResponseHasNoRelevantHeader() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseAlertIfResponseHasRelevantContent() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.getResponseHeader().addHeader(XBS_HEADER, HEADER_VALUE);
        // When
        scanHttpResponseReceive(msg);
        // THen
        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(HEADER_VALUE));
    }
}
