/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP development team
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
package org.zaproxy.zap.extension.pscanrules;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

import org.junit.Test;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class HeaderXssProtectionScannerUnitTest extends PassiveScannerTest<HeaderXssProtectionScanner> {

    @Override
    protected HeaderXssProtectionScanner createScanner() {
        return new HeaderXssProtectionScanner();
    }

    @Test
    public void noXssProtection () throws HttpMalformedHeaderException {
        
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                "Server: Apache-Coyote/1.1\r\n" +
                "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_XSS_PROTECTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
    }
    
    @Test
    public void emptyXssProtection () throws HttpMalformedHeaderException {
        
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                "Server: Apache-Coyote/1.1\r\n" +
                "X-XSS-Protection: \r\n" +
                "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_XSS_PROTECTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("X-XSS-Protection: "));
    }

    @Test
    public void xssProtection0 () throws HttpMalformedHeaderException {
        
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                "Server: Apache-Coyote/1.1\r\n" +
                "X-XSS-Protection: 0\r\n" +
                "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_XSS_PROTECTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("X-XSS-Protection: 0"));
    }

    @Test
    public void xssProtection1() throws HttpMalformedHeaderException {
        
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                "Server: Apache-Coyote/1.1\r\n" +
                "X-XSS-Protection: 1\r\n" +
                "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void xssProtection2() throws HttpMalformedHeaderException {
        
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                "Server: Apache-Coyote/1.1\r\n" +
                "X-XSS-Protection: 2\r\n" +
                "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_XSS_PROTECTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("X-XSS-Protection: 2"));
    }

    @Test
    public void noXssProtectionPlainTextLowNoBody() throws HttpMalformedHeaderException {
        
        rule.setAlertThreshold(AlertThreshold.LOW);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        
        msg.setResponseBody("");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                "Server: Apache-Coyote/1.1\r\n" +
                "Content-Type: text/plain;charset=us-ascii\r\n" +
                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void noXssProtectionPlainTextLowWithBody() throws HttpMalformedHeaderException {
        
        rule.setAlertThreshold(AlertThreshold.LOW);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        
        msg.setResponseBody("Blah");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                "Server: Apache-Coyote/1.1\r\n" +
                "Content-Type: text/plain;charset=us-ascii\r\n" +
                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_XSS_PROTECTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
    }

    @Test
    public void noXssProtectionPlainTextMedium() throws HttpMalformedHeaderException {
        
        rule.setAlertThreshold(AlertThreshold.MEDIUM);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        
        msg.setResponseBody("Blah");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                "Server: Apache-Coyote/1.1\r\n" +
                "Content-Type: text/plain;charset=us-ascii\r\n" +
                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void noXssProtectionPlainTextHigh() throws HttpMalformedHeaderException {
        
        rule.setAlertThreshold(AlertThreshold.HIGH);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        
        msg.setResponseBody("Blah");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                "Server: Apache-Coyote/1.1\r\n" +
                "Content-Type: text/plain;charset=us-ascii\r\n" +
                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void noXssProtectionRedirectLow() throws HttpMalformedHeaderException {
        
        rule.setAlertThreshold(AlertThreshold.LOW);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 301 Moved Permanently\r\n" +
                "Server: Apache-Coyote/1.1\r\n" +
                "Location: http://www.example.org/test2\r\n" +
                "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo(HttpHeader.X_XSS_PROTECTION));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo(""));
    }
    
    @Test
    public void noXssProtectionRedirectMed() throws HttpMalformedHeaderException {
        
        rule.setAlertThreshold(AlertThreshold.MEDIUM);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 301 Moved Permanently\r\n" +
                "Server: Apache-Coyote/1.1\r\n" +
                "Location: http://www.example.org/test2\r\n" +
                "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void noXssProtectionRedirectHigh() throws HttpMalformedHeaderException {
        
        rule.setAlertThreshold(AlertThreshold.HIGH);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 301 Moved Permanently\r\n" +
                "Server: Apache-Coyote/1.1\r\n" +
                "Location: http://www.example.org/test2\r\n" +
                "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }

}
