/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import fi.iki.elonen.NanoHTTPD;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.addon.oast.ExtensionOast;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link JavaDeserializationScanRule}. */
class JavaDeserializationScanRuleUnitTest extends ActiveScannerTest<JavaDeserializationScanRule> {

    // Base64 of a serialized String "hello".
    private static final String SERIALIZED_OBJECT = "rO0ABXQABWhlbGxv";
    private static final String OAST_HOST = "abc123.oast.example";

    private ExtensionOast extensionOast;

    @Override
    protected JavaDeserializationScanRule createScanner() {
        return new JavaDeserializationScanRule();
    }

    @BeforeEach
    void init() {
        nano.addHandler(new OkServerHandler("/abc"));

        extensionOast = mock(ExtensionOast.class);
        Control.initSingletonForTesting(
                Model.getSingleton(),
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT)));
        when(Control.getSingleton().getExtensionLoader().getExtension(ExtensionOast.class))
                .thenReturn(extensionOast);
    }

    @Test
    void shouldTargetJavaApps() {
        // Given
        TechSet techSet = techSet(Tech.JAVA);
        // Then
        assertThat(rule.targets(techSet), is(equalTo(true)));
    }

    @Test
    void shouldNotTargetNonJavaApps() {
        // Given
        TechSet techSet = techSet(Tech.PHP);
        // Then
        assertThat(rule.targets(techSet), is(equalTo(false)));
    }

    @Test
    void shouldNotSendMessagesIfNoValueIsASerializedObject() throws Exception {
        // Given
        rule.init(getHttpMessage("/abc?a=1&b=hello"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(0));
        verify(extensionOast, never()).registerAlertAndGetPayload(any());
    }

    @Test
    void shouldReplaceSerializedObjectInQueryParameter() throws Exception {
        // Given
        when(extensionOast.registerAlertAndGetPayload(any())).thenReturn(OAST_HOST);
        rule.init(getHttpMessage("/abc?a=1&session=" + SERIALIZED_OBJECT), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(1));
        assertThat(
                httpMessagesSent.get(0).getRequestHeader().getURI().getQuery(),
                is(equalTo("a=1&session=" + expectedAttack(SERIALIZED_OBJECT))));
    }

    @Test
    void shouldReplaceSerializedObjectInCookie() throws Exception {
        // Given
        when(extensionOast.registerAlertAndGetPayload(any())).thenReturn(OAST_HOST);
        HttpMessage msg = getHttpMessage("/abc");
        msg.getRequestHeader().setHeader("Cookie", "session=" + SERIALIZED_OBJECT);
        scannerParam.setTargetParamsInjectable(ScannerParam.TARGET_COOKIE);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(1));
        assertThat(
                httpMessagesSent.get(0).getRequestHeader().getHeader("Cookie"),
                is(equalTo("session=" + expectedAttack(SERIALIZED_OBJECT))));
    }

    @Test
    void shouldKeepUrlSafeAlphabetOfOriginalValue() throws Exception {
        // Given
        String urlSafeValue = "rO0ABXQABW_l-Gxv";
        when(extensionOast.registerAlertAndGetPayload(any())).thenReturn(OAST_HOST);
        rule.init(getHttpMessage("/abc?session=" + urlSafeValue), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(1));
        assertThat(
                httpMessagesSent.get(0).getRequestHeader().getURI().getQuery(),
                is(equalTo("session=" + expectedAttack(urlSafeValue))));
    }

    @Test
    void shouldScanOtherParametersEvenInCaseOfIoException() throws Exception {
        // Given
        when(extensionOast.registerAlertAndGetPayload(any()))
                .thenThrow(IOException.class)
                .thenReturn(OAST_HOST);
        rule.init(
                getHttpMessage("/abc?a=" + SERIALIZED_OBJECT + "&b=" + SERIALIZED_OBJECT), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(1));
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(502)));
        assertThat(wasc, is(equalTo(20)));
        assertThat(tags.size(), is(equalTo(6)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2025_A08_INTEGRITY_FAIL.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A08_INTEGRITY_FAIL.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A08_INSECURE_DESERIAL.getTag()),
                is(equalTo(true)));
        assertThat(tags.containsKey(ExtensionOast.OAST_ALERT_TAG_KEY), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.QA_FULL.getTag()), is(equalTo(true)));
        assertThat(tags.containsKey(PolicyTag.PENTEST.getTag()), is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2025_A08_INTEGRITY_FAIL.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2025_A08_INTEGRITY_FAIL.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A08_INTEGRITY_FAIL.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A08_INTEGRITY_FAIL.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A08_INSECURE_DESERIAL.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A08_INSECURE_DESERIAL.getValue())));
        assertThat(
                tags.get(ExtensionOast.OAST_ALERT_TAG_KEY),
                is(equalTo(ExtensionOast.OAST_ALERT_TAG_VALUE)));
    }

    @Test
    void shouldHaveExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts, hasSize(1));
        Alert alert = alerts.get(0);
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alert.getCweId(), is(equalTo(502)));
    }

    private static String expectedAttack(String originalValue) {
        return JavaSerializedPayload.encodeLike(
                originalValue, JavaSerializedPayload.create(OAST_HOST));
    }

    private static class OkServerHandler extends NanoServerHandler {

        OkServerHandler(String path) {
            super(path);
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            return newFixedLengthResponse(
                    NanoHTTPD.Response.Status.OK, NanoHTTPD.MIME_PLAINTEXT, "OK");
        }
    }
}
