/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.AbstractAppFilePluginUnitTest;
import org.zaproxy.addon.commonlib.CommonAlertTag;

/** Unit test for {@link TraceAxdScanRule}. */
class TraceAxdScanRuleUnitTest extends AbstractAppFilePluginUnitTest<TraceAxdScanRule> {

    private static final String RELEVANT_BODY = "<html><H1>Application Trace</H1></html>";
    private static final String IRRELEVANT_BODY = "<html><title>Some Page</title></html>";

    @Override
    protected TraceAxdScanRule createScanner() {
        return new TraceAxdScanRule();
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionAscanRulesBeta());
    }

    @Override
    @Test
    public void shouldAlertWhenRequestIsSuccessful() throws Exception {
        // Given
        String path = "/trace.axd";
        this.nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(
                                Response.Status.OK, NanoHTTPD.MIME_HTML, RELEVANT_BODY)));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals(1, httpMessagesSent.size());
        Alert alert = alertsRaised.get(0);
        assertEquals(Alert.RISK_MEDIUM, alert.getRisk());
        assertEquals(Alert.CONFIDENCE_MEDIUM, alert.getConfidence());
    }

    @Override
    @Test
    public void shouldAlertWhenRequestIsUnauthorizedAtLowThreshold() throws Exception {
        // Given
        String path = "/trace.axd";
        this.nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(
                                Response.Status.UNAUTHORIZED,
                                NanoHTTPD.MIME_HTML,
                                IRRELEVANT_BODY)));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.setAlertThreshold(AlertThreshold.LOW);
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertEquals(1, httpMessagesSent.size());
        Alert alert = alertsRaised.get(0);
        assertEquals(Alert.RISK_INFO, alert.getRisk());
        assertEquals(Alert.CONFIDENCE_LOW, alert.getConfidence());
    }

    @Test
    void shouldNotAlertWhenRequestIsSuccessfulButContentNotRelevant() throws Exception {
        // Given
        String path = "/trace.axd";
        this.nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(
                                Response.Status.OK, NanoHTTPD.MIME_HTML, IRRELEVANT_BODY)));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        Map<String, String> tags = ((TraceAxdScanRule) rule).getAlertTags();
        // Then
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE.getValue())));
    }
}
