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
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.mockito.Mockito;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

public class CookieSecureFlagScannerUnitTest extends PassiveScannerTest<CookieSecureFlagScanner> {

    private Model model;

    @Override
    protected CookieSecureFlagScanner createScanner() {
        rule = new CookieSecureFlagScanner();
        // Mock the model and options
        model = Mockito.mock(Model.class);
        OptionsParam options = new OptionsParam();
        ZapXmlConfiguration conf = new ZapXmlConfiguration();
        options.load(conf);
        when(model.getOptionsParam()).thenReturn(options);
        rule.setModel(model);
        return rule;
    }

    @Test
    public void httpNoSecureFlag() throws HttpMalformedHeaderException {
        
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET http://www.example.com/test/ HTTP/1.1");
        
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                "Server: Apache-Coyote/1.1\r\n" +
                "Set-Cookie: test=123; Path=/;\r\n" +
                "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }
    
    @Test
    public void httpsNoSecureFlag() throws HttpMalformedHeaderException {
        
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                "Server: Apache-Coyote/1.1\r\n" +
                "Set-Cookie: test=123; Path=/;\r\n" +
                "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("test"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("Set-Cookie: test"));
    }

    @Test
    public void httpsSecureFlag() throws HttpMalformedHeaderException {
        
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                "Server: Apache-Coyote/1.1\r\n" +
                "Set-Cookie: test=123; Path=/; Secure;\r\n" +
                "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }
    
    @Test
    public void secondCookieNoSecureFlag() throws HttpMalformedHeaderException {
        
        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                "Server: Apache-Coyote/1.1\r\n" +
                "Set-Cookie: hasatt=test123; Path=/; Secure; HttpOnly\r\n" +
                "Set-Cookie: test=123; Path=/;\r\n" +
                "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("test"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("Set-Cookie: test"));
    }
    
    @Test
    public void cookieOnIgnoreList() throws HttpMalformedHeaderException {
        model.getOptionsParam().getConfig().setProperty(RuleConfigParam.RULE_COOKIE_IGNORE_LIST, "aaaa,test,bbb");

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                "Server: Apache-Coyote/1.1\r\n" +
                "Set-Cookie: test=123; Path=/;\r\n" +
                "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    public void cookieNotOnIgnoreList() throws HttpMalformedHeaderException {
        model.getOptionsParam().getConfig().setProperty(RuleConfigParam.RULE_COOKIE_IGNORE_LIST, "aaaa,bbb,ccc");

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");
        
        msg.setResponseBody("<html></html>");
        msg.setResponseHeader(
                "HTTP/1.1 200 OK\r\n" +
                "Server: Apache-Coyote/1.1\r\n" +
                "Set-Cookie: test=123; Path=/;\r\n" +
                "Content-Type: text/html;charset=ISO-8859-1\r\n" +
                "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(1));
        assertThat(alertsRaised.get(0).getParam(), equalTo("test"));
        assertThat(alertsRaised.get(0).getEvidence(), equalTo("Set-Cookie: test"));
    }
}
