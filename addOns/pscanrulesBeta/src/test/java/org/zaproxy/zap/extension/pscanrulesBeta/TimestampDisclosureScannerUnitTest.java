/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP development team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.zaproxy.zap.extension.pscanrulesBeta;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.Before;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

import static org.junit.Assert.assertEquals;

public class TimestampDisclosureScannerUnitTest extends PassiveScannerTest<TimestampDisclosureScanner> {
    private HttpMessage msg;

    @Before
    public void before() throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
    }

    @Override
    protected TimestampDisclosureScanner createScanner() {
        return new TimestampDisclosureScanner();
    }

    @Test
    public void shouldNotRaiseAlertOnSTSHeader() throws Exception {
        // Given
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Apache-Coyote/1.1\r\n" + "Strict-Transport-Security: max-age=15552000; includeSubDomains\r\n");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertEquals(alertsRaised.size(), 0);
    }

}
