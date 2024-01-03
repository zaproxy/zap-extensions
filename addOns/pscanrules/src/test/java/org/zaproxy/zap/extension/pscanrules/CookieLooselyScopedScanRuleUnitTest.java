/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.ruleconfig.RuleConfigParam;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

/**
 * @author Vahid Rafiei (@vahid_r)
 */
class CookieLooselyScopedScanRuleUnitTest extends PassiveScannerTest<CookieLooselyScopedScanRule> {

    private Model model;

    @Override
    protected CookieLooselyScopedScanRule createScanner() {
        rule = new CookieLooselyScopedScanRule();
        // Mock the model and options
        model = mock(Model.class, withSettings().strictness(Strictness.LENIENT));
        OptionsParam options = new OptionsParam();
        ZapXmlConfiguration conf = new ZapXmlConfiguration();
        options.load(conf);
        when(model.getOptionsParam()).thenReturn(options);
        rule.setModel(model);
        return rule;
    }

    private HttpMessage createBasicMessage() throws HttpMalformedHeaderException {
        HttpMessage msg = new HttpMessage();
        msg.setResponseHeader("HTTP/1.1 200 OK\r\n" + "Server: Apache-Coyote/1.1\r\n");

        return msg;
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(565)));
        assertThat(wasc, is(equalTo(15)));
        assertThat(tags.size(), is(equalTo(3)));
        assertAlertTags(tags);
    }

    private static void assertAlertTags(Map<String, String> tags) {
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A08_INTEGRITY_FAIL.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A08_INTEGRITY_FAIL.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A08_INTEGRITY_FAIL.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS.getValue())));
    }

    @Test
    void shouldReturnExpectedExampleAlert() {
        // Given / When
        List<Alert> alerts = rule.getExampleAlerts();
        // Then
        assertThat(alerts, hasSize(1));
        Alert alert = alerts.get(0);
        assertAlertTags(alert.getTags());
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_INFO)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_LOW)));
        assertThat(alert.getCweId(), is(equalTo(565)));
        assertThat(alert.getWascId(), is(equalTo(15)));
    }

    @Test
    void shouldNotRaiseAlertIfThereIsNoCookieInResponseHeader() throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET /admin/roles/ HTTP/1.1");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldNotRaiseAlertIfCookieDomainIsNotSet() throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET /admin/roles/ HTTP/1.1");
        msg.getResponseHeader().setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldNotRaiseAlertIfHostDomainStartsWithDotAndCookieDomainIsNotSet() throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET .local.test.com HTTP/1.1");
        msg.getResponseHeader().setHeader(HttpResponseHeader.SET_COOKIE, "a=b;");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldRaiseAlertIfHostDomainIsDifferentFromCookieDomain() throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET http://dev.test.org HTTP/1.1");
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=local.yahoo.com;");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
    }

    @Test
    void shouldDomainComparisonBeCaseInsensitive() throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET http://TesT.org HTTP/1.1");
        msg.getResponseHeader().setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=tEst.org;");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldNotRaiseAlertIfHostDomainAndCookieDomainAreTheSameAndDomainsAreNotSecondLevel()
            throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET http://test.example.com HTTP/1.1");
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=test.example.com;");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldRaiseAlertIfHostDomainHasMoreSubDomainsThanCookieDomain() throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET http://test.example.com HTTP/1.1");
        msg.getResponseHeader().setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=example.com;");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
    }

    @Test
    void shouldNotRaiseAlertIfHostDomainHasLessSubDomainsThanCookieDomain() throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET http://example.com HTTP/1.1");
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=stage.example.com;");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(0));
    }

    @Test
    void shouldRaiseAlertIfRightMostDomainsMatch() throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET http://test.example.com/admin/roles HTTP/1.1");
        msg.getResponseHeader().setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=.example.com");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), is(1));
    }

    @Test
    void shouldScanCookieDomainWithJustTld() throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET http://example.com/ HTTP/1.1");
        msg.getResponseHeader().setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=com");

        // When / Then
        assertDoesNotThrow(() -> scanHttpResponseReceive(msg));
    }

    @Test
    void shouldScanHostWithoutTld() throws Exception {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET http://intranet/ HTTP/1.1");
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=subdomain.intranet");

        // When / Then
        assertDoesNotThrow(() -> scanHttpResponseReceive(msg));
    }

    @Test
    void shouldNotAlertWhenCookieOnIgnoreList() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET http://test.example.com/admin/roles HTTP/1.1");
        msg.getResponseHeader()
                .setHeader(HttpResponseHeader.SET_COOKIE, "aaaa=b;domain=.example.com");
        model.getOptionsParam()
                .getConfig()
                .setProperty(RuleConfigParam.RULE_COOKIE_IGNORE_LIST, "aaaa,bbb,ccc");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), equalTo(0));
    }

    @Test
    void shouldAlertWhenCookieNotOnIgnoreList() throws HttpMalformedHeaderException {
        // Given
        HttpMessage msg = createBasicMessage();
        msg.setRequestHeader("GET http://test.example.com/admin/roles HTTP/1.1");
        msg.getResponseHeader().setHeader(HttpResponseHeader.SET_COOKIE, "a=b;domain=.example.com");
        model.getOptionsParam()
                .getConfig()
                .setProperty(RuleConfigParam.RULE_COOKIE_IGNORE_LIST, "aaaa,bbb,ccc");

        // When
        scanHttpResponseReceive(msg);

        // Then
        assertThat(alertsRaised.size(), equalTo(1));
    }

    @Test
    @Override
    public void shouldHaveValidReferences() {
        super.shouldHaveValidReferences();
    }
}
