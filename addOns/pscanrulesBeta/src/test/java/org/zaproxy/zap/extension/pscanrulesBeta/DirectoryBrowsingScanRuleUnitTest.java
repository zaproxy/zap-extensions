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
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpStatusCode;

public class DirectoryBrowsingScanRuleUnitTest
        extends PassiveScannerTest<DirectoryBrowsingScanRule> {

    private HttpMessage createMessage() throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://example.com", false));

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.OK);
        msg.getResponseHeader().setHeader(HttpResponseHeader.CONTENT_TYPE, "text/html");
        return msg;
    }

    @Override
    protected DirectoryBrowsingScanRule createScanner() {
        return new DirectoryBrowsingScanRule();
    }

    @Test
    public void shouldNotRaiseAlertIfResponseBodyIsEmpty() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldNotRaiseAlertIfResponseBodyIsIrrelevant() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseBody("<html><H1>Some Title</H1></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldRaiseAlertIfResponseContainsApacheStyleIndex() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseBody("<html><title>Index of /htdocs</title></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
    }

    @Test
    public void shouldRaiseAlertIfResponseContainsIisStyleIndex() throws URIException {
        // Given
        HttpMessage msg = createMessage();
        msg.setResponseBody(
                "<html><head><title>somesite.net - /site/</title></head><body><H1>somesite.net - /site/</H1><hr><pre><A HREF=\"/\">[To Parent Directory]</A><br><br> 6/12/2014  3:25 AM        &lt;dir&gt; <A HREF=\"/site/file.ext/\">file.ext</A><br></pre><hr></body></html>");
        // When
        scanHttpResponseReceive(msg);
        // Then
        assertThat(alertsRaised.size(), equalTo(1));
    }
}
