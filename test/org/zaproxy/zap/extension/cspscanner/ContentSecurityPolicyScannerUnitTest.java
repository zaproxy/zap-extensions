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
package org.zaproxy.zap.extension.cspscanner;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

import org.junit.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.pscanrulesAlpha.PassiveScannerTest;

public class ContentSecurityPolicyScannerUnitTest extends PassiveScannerTest {

    @Override
    protected PluginPassiveScanner createScanner() {
        return new ContentSecurityPolicyScanner();
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionContentSecurityPolicyScanner());
    }

    @Test
    public void exampleBadCsp() throws HttpMalformedHeaderException {

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET https://www.example.com/test/ HTTP/1.1");

        msg.setResponseBody("<html></html>");
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n"
                + "Server: Apache-Coyote/1.1\r\n"
                + "Content-Security-Policy: default-src: 'none'; report_uri /__cspreport__\r\n"
                + "Content-Type: text/html;charset=ISO-8859-1\r\n"
                + "Content-Length: " + msg.getResponseBody().length() + "\r\n");
        rule.scanHttpResponseReceive(msg, -1, this.createSource(msg));

        assertThat(alertsRaised.size(), equalTo(2));

        assertThat(alertsRaised.get(0).getName(), equalTo("CSP Scanner: Notices"));
        assertThat(alertsRaised.get(0).getDescription(), equalTo(
                "Errors:\n"
                + "1:12: Expecting directive-value but found U+003A (:). Non-ASCII and non-printable characters must be percent-encoded.\n"
                + "1:22: Unrecognised directive-name: \"report\".\n"
                + "1:28: Expecting directive-value but found U+005F (_). Non-ASCII and non-printable characters must be percent-encoded.\n"));
        assertThat(alertsRaised.get(0).getEvidence(),
                equalTo("default-src: 'none'; report_uri /__cspreport__"));
        assertThat(alertsRaised.get(0).getRisk(), equalTo(Alert.RISK_LOW));
        assertThat(alertsRaised.get(0).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));

        assertThat(alertsRaised.get(1).getName(), equalTo("CSP Scanner: Wildcard Directive"));
        assertThat(alertsRaised.get(1).getDescription(), equalTo(
                "The following directives either allow wildcard sources (or ancestors), are not defined, or are overly broadly defined: \n"
                + "script-src, style-src, img-src, connect-src, frame-src, frame-ancestor, font-src, media-src, object-src, manifest-src, "
                + "worker-src, prefetch-src"));
        assertThat(alertsRaised.get(1).getEvidence(),
                equalTo("default-src: 'none'; report_uri /__cspreport__"));
        assertThat(alertsRaised.get(1).getRisk(), equalTo(Alert.RISK_MEDIUM));
        assertThat(alertsRaised.get(1).getConfidence(), equalTo(Alert.CONFIDENCE_MEDIUM));
    }
}
