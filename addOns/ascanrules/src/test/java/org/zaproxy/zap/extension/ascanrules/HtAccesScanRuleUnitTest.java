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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.AbstractAppFilePluginUnitTest;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link HtAccessScanRule}. */
class HtAccesScanRuleUnitTest extends AbstractAppFilePluginUnitTest<HtAccessScanRule> {

    private static final String URL = "/.htaccess";
    private static final String HTACCESS_BODY = "order allow,deny";

    private static final String DEFAULT_BODY =
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
                    + "<html><head></head><body>\n"
                    + "<h1>Error Log for testing</h1>\n"
                    + "<p>Blah blah blah.</p>\n"
                    + "</body></html>";

    @Override
    protected HtAccessScanRule createScanner() {
        return new HtAccessScanRule();
    }

    @BeforeEach
    void setup() {
        this.setBody(HTACCESS_BODY);
    }

    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionAscanRules());
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = ((HtAccessScanRule) rule).getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(94)));
        assertThat(wasc, is(equalTo(14)));
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

    @Test
    void shouldNotAlertIfNonHtaccessFileFoundStdThreshold() throws Exception {
        // Given
        nano.addHandler(new MiscOkResponse());
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfNonHtaccessFileFoundLowThreshold() throws Exception {
        // Given
        nano.addHandler(new MiscOkResponse());
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        rule.setAlertThreshold(AlertThreshold.LOW);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @ParameterizedTest
    @ValueSource(strings = {"application/json", "application/xml"})
    void shouldNotAlertIfResponseIsJsonOrXml(String contentType) throws Exception {
        // Given
        nano.addHandler(new MiscOkResponse(URL, contentType));
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    void shouldNotAlertIfResponseIsEmpty() throws Exception {
        // Given
        nano.addHandler(new MiscOkResponse(""));
        HttpMessage message = getHttpMessage(URL);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    private static class MiscOkResponse extends NanoServerHandler {

        String contentType = "text.html";
        String content = DEFAULT_BODY;

        public MiscOkResponse() {
            super(URL);
        }

        public MiscOkResponse(String content) {
            super(URL);
            this.content = content;
        }

        public MiscOkResponse(String path, String contentType) {
            super(path);
            this.contentType = contentType;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            return newFixedLengthResponse(Response.Status.OK, contentType, content);
        }
    }
}
