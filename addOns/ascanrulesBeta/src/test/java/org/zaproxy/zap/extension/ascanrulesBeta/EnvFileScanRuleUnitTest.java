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
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.AbstractAppFilePluginUnitTest;
import org.zaproxy.addon.commonlib.CommonAlertTag;

/** Unit test for {@link EnvFileScanRule}. */
class EnvFileScanRuleUnitTest extends AbstractAppFilePluginUnitTest<EnvFileScanRule> {

    private static final String RELEVANT_BODY =
            "# Never expose this to the internet\n"
                    + "DB_CONNECTION=mysql\n"
                    + "DB_HOST=gcomlnk.solutions\n"
                    + "DB_PORT=3306\n"
                    + "DB_DATABASE=gcom_tbot\n"
                    + "DB_USERNAME=gcom_french\n"
                    + "DB_PASSWORD=secure123";
    private static final String RELEVANT_BODY_NO_COMMENT =
            "DB_CONNECTION=mysql\n"
                    + "DB_HOST=gcomlnk.solutions\n"
                    + "DB_PORT=3306\n"
                    + "DB_DATABASE=gcom_tbot\n"
                    + "DB_USERNAME=gcom_french\n"
                    + "DB_PASSWORD=secure123";
    private static final String IRRELEVANT_BODY =
            "<html><title>Some Page</title>"
                    + "<body><div id='this'><a href='#'></a></div>"
                    + "<script> $(\"#this\").css(\"display:none;\")<script> "
                    + "<div> Then there's at least a little more text in a webpage that would "
                    + "make the content longer than what a env file would look like"
                    + "<span><blink><marquee>hopefully the rule won't pick this up</marquee></blink></span>"
                    + "yes, I know those tags don't work</div>"
                    + "</body></html>";

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
        // Override this to do nothing
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"application/octet-stream"})
    void shouldAlertWhenRequestIsSuccessfulWithExpectedContent(String contentType)
            throws Exception {
        // Given
        String path = "/.env";
        this.nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(Response.Status.OK, contentType, RELEVANT_BODY)));
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

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"application/octet-stream"})
    void shouldAlertWhenRequestIsSuccessfulWithExpectedContentNoComment(String contentType)
            throws Exception {
        // Given
        String path = "/.env";
        this.nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(
                                Response.Status.OK, contentType, RELEVANT_BODY_NO_COMMENT)));
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

    @Test
    void shouldNotAlertWhenRequestIsSuccessfulButContentIsRelevantWrongType() throws Exception {
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
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertWhenRequestIsSuccessfulButContentIsIrrelevantCorrectType() throws Exception {
        // Given
        String path = "/.env";
        this.nano.addHandler(
                createHandler(
                        path, newFixedLengthResponse(Response.Status.OK, null, IRRELEVANT_BODY)));
        HttpMessage msg = this.getHttpMessage(path);
        rule.init(msg, this.parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertWhenResponseIsTooLong() throws Exception {
        // Given
        String path = "/.env";
        this.nano.addHandler(
                createHandler(
                        path,
                        newFixedLengthResponse(
                                Response.Status.OK, null, IRRELEVANT_BODY + RELEVANT_BODY)));
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
        Map<String, String> tags = ((EnvFileScanRule) rule).getAlertTags();
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
