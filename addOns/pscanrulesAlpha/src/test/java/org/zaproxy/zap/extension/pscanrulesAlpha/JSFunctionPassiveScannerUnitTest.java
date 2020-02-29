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
package org.zaproxy.zap.extension.pscanrulesAlpha;

import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.*;

import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.Test;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;

public class JSFunctionPassiveScannerUnitTest extends PassiveScannerTest<JSFunctionPassiveScanner> {

    @Override
    protected JSFunctionPassiveScanner createScanner() {
        return new JSFunctionPassiveScanner();
    }

    @Test
    public void shouldRaiseAlertGivenMatch() throws URIException {
        // Test value in message taken from xml/js-function-list.txt
        HttpMessage msg = createMessage("bypassSecurityTrustScript");
        Source source = createSource(msg);

        rule.scanHttpResponseReceive(msg, -1, source);

        assertThat(alertsRaised, hasSize(1));
    }

    @Test
    public void shouldNotRaiseAlertGivenNoMatch() throws URIException {
        HttpMessage msg = createMessage("");
        Source source = createSource(msg);

        rule.scanHttpResponseReceive(msg, -1, source);

        assertThat(alertsRaised, empty());
    }

    private HttpMessage createMessage(String content) throws URIException {
        HttpRequestHeader requestHeader = new HttpRequestHeader();
        requestHeader.setURI(new URI("http://test.com", false));

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader(requestHeader);
        msg.getResponseHeader().setStatusCode(HttpStatusCode.NOT_FOUND);
        msg.setResponseBody("<html><body>" + content + "</body></html>");
        return msg;
    }
}
