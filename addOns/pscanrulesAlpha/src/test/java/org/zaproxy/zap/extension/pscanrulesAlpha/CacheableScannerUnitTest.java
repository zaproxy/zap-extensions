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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

import java.util.Date;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.httpclient.util.DateUtil;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

public class CacheableScannerUnitTest extends PassiveScannerTest<CacheableScanner> {

    private HttpMessage createMessage() throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setMethod("GET");
        requestHeader.setURI(new URI("https://example.com/fred/", false));

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        return msg;
    }

    @Override
    protected CacheableScanner createScanner() {
        return new CacheableScanner();
    }

    @Test
    public void scannerNameShouldMatch() {
        // Quick test to verify scanner name which is used in the policy dialog but not
        // alerts

        // Given
        CacheableScanner thisScanner = createScanner();
        // Then
        assertThat(thisScanner.getName(), equalTo("Content Cacheability"));
    }

    @Test
    public void shouldNotCauseExceptionWhenExpiresHeaderHasZeroValue()
            throws URIException, HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Cache-Control: must-revalidate,private\r\n"
                        + "Pragma: must-revalidate,no-cache\r\n"
                        + "Content-Type: text/xml;charset=UTF-8\r\n"
                        + "Expires: 0\r\n"
                        + // http-date expected, Ex: "Wed, 21 Oct 2015 07:28:00 GMT"
                        "Date: "
                        + DateUtil.formatDate(new Date())
                        + "\r\n\r\n");
        // When
        rule.scanHttpResponseReceive(msg, -1, createSource(msg));
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
    }
}
