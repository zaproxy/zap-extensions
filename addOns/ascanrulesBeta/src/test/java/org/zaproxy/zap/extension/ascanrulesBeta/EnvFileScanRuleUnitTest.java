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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.AbstractAppFilePluginUnitTest;

/** Unit test for {@link EnvFileScanRule}. */
class EnvFileScanRuleUnitTest extends AbstractAppFilePluginUnitTest<EnvFileScanRule> {

    private static final String RELEVANT_BODY =
            "DB_CONNECTION=mysql\n"
                    + "DB_HOST=gcomlnk.solutions\n"
                    + "DB_PORT=3306\n"
                    + "DB_DATABASE=gcom_tbot\n"
                    + "DB_USERNAME=gcom_french\n"
                    + "DB_PASSWORD=secure123";
    private static final String IRRELEVANT_BODY = "<html><title>Some Page</title></html>";

    @Override
    protected EnvFileScanRule createScanner() {
        return new EnvFileScanRule();
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionAscanRulesBeta());
    }

    @Override
    @Test
    public void shouldAlertWhenRequestIsSuccessful() throws Exception {
        // Given
        String path = "/.env";
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
        String path = "/.env";
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
        String path = "/.env";
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
}
