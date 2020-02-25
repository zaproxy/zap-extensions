/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertThat;

import org.junit.Test;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class CacheControlScannerUnitTest extends PassiveScannerTest<CacheControlScanner> {

    @Override
    protected CacheControlScanner createScanner() {
        return new CacheControlScanner();
    }

    @Test
    public void httpRequest() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void httpsAllPresentCacheRequest() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void shouldIgnoreEmptyHttpsResponses() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        // When
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void httpsMissingNoCacheRequest() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Cache-Control: no-store, must-revalidate\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.CACHE_CONTROL));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("no-store, must-revalidate"));
    }

    @Test
    public void httpsMissingNoStoreCacheRequest() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Cache-Control: no-cache, must-revalidate\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.CACHE_CONTROL));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("no-cache, must-revalidate"));
    }

    @Test
    public void httpsMissingMustRevalidateCacheRequest() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Cache-Control: no-store, no-cache\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.CACHE_CONTROL));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("no-store, no-cache"));
    }

    @Test
    public void httpsGoodPragmaCacheRequest() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                        + "Pragma: no-cache\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void httpsBadPragmaCacheRequest() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Cache-Control: no-cache, no-store, must-revalidate\r\n"
                        + "Pragma: cache\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.PRAGMA));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("cache"));
    }

    @Test
    public void httpsRedirectLowCacheRequest() throws HttpMalformedHeaderException {

        rule.setAlertThreshold(AlertThreshold.LOW);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 301 Moved Permanently\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Location: http://www.example.org/test2\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.CACHE_CONTROL));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
    }

    @Test
    public void httpsRedirectMedCacheRequest() throws HttpMalformedHeaderException {

        rule.setAlertThreshold(AlertThreshold.MEDIUM);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 301 Moved Permanently\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Location: http://www.example.org/test2\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void httpsRedirectHighCacheRequest() throws HttpMalformedHeaderException {

        rule.setAlertThreshold(AlertThreshold.HIGH);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 301 Moved Permanently\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Location: http://www.example.org/test2\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void httpsErrorLowCacheRequest() throws HttpMalformedHeaderException {

        rule.setAlertThreshold(AlertThreshold.LOW);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 401 Unauthorized\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.CACHE_CONTROL));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
    }

    @Test
    public void httpsErrorMedCacheRequest() throws HttpMalformedHeaderException {

        rule.setAlertThreshold(AlertThreshold.MEDIUM);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 401 Unauthorized\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void httpsErrorHighCacheRequest() throws HttpMalformedHeaderException {

        rule.setAlertThreshold(AlertThreshold.HIGH);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 401 Unauthorized\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void httpsJavaScriptLowCacheRequest() throws HttpMalformedHeaderException {

        rule.setAlertThreshold(AlertThreshold.LOW);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test.js HTTP/1.1");

        msg.setResponseBody("STUFF");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/javascript;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.CACHE_CONTROL));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
    }

    @Test
    public void httpsJavaScriptMedCacheRequest() throws HttpMalformedHeaderException {

        rule.setAlertThreshold(AlertThreshold.MEDIUM);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test.js HTTP/1.1");

        msg.setResponseBody("STUFF");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/javascript;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void httpsJavaScriptHighCacheRequest() throws HttpMalformedHeaderException {

        rule.setAlertThreshold(AlertThreshold.HIGH);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test.js HTTP/1.1");

        msg.setResponseBody("STUFF");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n"
                        + "Server: Apache-Coyote/1.1\r\n"
                        + "Content-Type: text/javascript;charset=ISO-8859-1\r\n"
                        + "Content-Length: "
                        + msg.getResponseBody().length()
                        + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }
}
