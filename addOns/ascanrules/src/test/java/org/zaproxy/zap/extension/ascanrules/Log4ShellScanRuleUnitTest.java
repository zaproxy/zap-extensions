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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasKey;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import fi.iki.elonen.NanoHTTPD;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;

class Log4ShellScanRuleUnitTest extends ActiveScannerTest<Log4ShellScanRule> {

    private ExtensionOast extensionOast;

    @Override
    protected Log4ShellScanRule createScanner() {
        return new Log4ShellScanRule();
    }

    @BeforeEach
    void init() throws Exception {
        nano.addHandler(new Log4ShellServerHandler("/abc"));
        HttpMessage httpMessageToTest = getHttpMessage("/abc?test=123");

        extensionOast = mock(ExtensionOast.class);
        Control.initSingletonForTesting(Model.getSingleton(), mock(ExtensionLoader.class));
        when(Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class))
                .thenReturn(extensionOast);

        rule.init(httpMessageToTest, parent);
    }

    @Test
    void shouldTargetJavaApps() {
        // Given
        TechSet techSet = techSet(Tech.JAVA);
        // Then
        assertThat(rule.targets(techSet), is(equalTo(true)));
    }

    @Test
    void shouldSendHttpMessageForEachPayload() throws Exception {
        // Given
        when(extensionOast.registerAlertAndGetPayload(any())).thenReturn("PAYLOAD");

        // When
        rule.scan();

        // Then
        assertThat(httpMessagesSent, hasSize(Log4ShellScanRule.ATTACK_PATTERN_COUNT));
    }

    @Test
    void shouldSendAllPayloadsEvenInCaseOfIoException() throws Exception {
        // Given
        when(extensionOast.registerAlertAndGetPayload(any()))
                .thenReturn("PAYLOAD1")
                .thenThrow(IOException.class)
                .thenReturn("PAYLOAD");

        // When
        rule.scan();

        // Then
        assertThat(httpMessagesSent, hasSize(Log4ShellScanRule.ATTACK_PATTERN_COUNT - 1));
    }

    @Test
    void shouldStopSendingPayloadsOnNonIoException() throws Exception {
        // Given
        when(extensionOast.registerAlertAndGetPayload(any()))
                .thenReturn("PAYLOAD1")
                .thenThrow(NullPointerException.class)
                .thenReturn("PAYLOAD");

        // When
        rule.scan();

        // Then
        assertThat(httpMessagesSent, hasSize(1));
    }

    @Test
    void shouldReturnExpectedNumberOfAlertTags() {
        // Given / When
        Map<String, String> alertTags = rule.getAlertTags();
        // Then
        assertThat(alertTags.size(), is(equalTo(6)));
    }

    @Test
    void shouldReturnExpectedExampleAlerts() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        Alert alert1 = alerts.get(0);
        Alert alert2 = alerts.get(1);
        // Then
        assertThat(alerts.size(), is(equalTo(2)));
        assertThat(alert1.getAlertRef(), is(equalTo("40043-1")));
        assertThat(alert1.getTags().size(), is(equalTo(6)));
        assertThat(alert1.getTags(), hasKey("CWE-117"));
        assertThat(alert1.getTags().containsKey("CVE-2021-44228"), is(equalTo(true)));
        assertThat(alert1.getName(), is(equalTo("Log4Shell (CVE-2021-44228)")));
        assertThat(alert2.getAlertRef(), is(equalTo("40043-2")));
        assertThat(alert2.getTags().containsKey("CVE-2021-45046"), is(equalTo(true)));
        assertThat(alert2.getTags().size(), is(equalTo(6)));
        assertThat(alert2.getTags(), hasKey("CWE-117"));
        assertThat(alert2.getName(), is(equalTo("Log4Shell (CVE-2021-45046)")));
    }

    @Test
    @Override
    public void shouldHaveValidReferences() {
        super.shouldHaveValidReferences();
    }

    private static class Log4ShellServerHandler extends NanoServerHandler {
        public Log4ShellServerHandler(String path) {
            super(path);
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            return newFixedLengthResponse(
                    NanoHTTPD.Response.Status.OK, NanoHTTPD.MIME_PLAINTEXT, "Log4Shell");
        }
    }
}
