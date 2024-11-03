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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.io.IOException;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.core.scanner.ScannerParam;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link LdapInjectionScanRule}. */
class LdapInjectionScanRuleUnitTest extends ActiveScannerTest<LdapInjectionScanRule> {

    private static final String DEFAULT_RESPONSE_STRING = "<html><body></body></html>";

    @Override
    protected LdapInjectionScanRule createScanner() {
        return new LdapInjectionScanRule();
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(90)));
        assertThat(wasc, is(equalTo(29)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_INPV_06_LDAPI.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A03_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A03_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A01_INJECTION.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A01_INJECTION.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_INPV_06_LDAPI.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_INPV_06_LDAPI.getValue())));
    }

    @Test
    void shouldTargetExpectedTech() {
        // Given / When
        TechSet allButLdap = techSetWithout(LdapInjectionScanRule.LDAP);
        TechSet justLdap = techSet(LdapInjectionScanRule.LDAP);

        // Then
        assertThat(rule.targets(allButLdap), is(equalTo(false)));
        assertThat(rule.targets(justLdap), is(equalTo(true)));
    }

    @Test
    void shouldSkipUrlParams() {
        // Given
        HttpMessage msg = createMessage("/param/test/");
        rule.init(msg, parent);
        scannerParam.setTargetParamsInjectable(ScannerParam.TARGET_URLPATH);
        // When
        rule.scan();
        // Then
        assertThat(countMessagesSent, is(equalTo(0)));
    }

    @Test
    void shouldNotAlertIfRandomBodyIsEmpty() throws IOException {
        // Given
        String path = "/shouldNotAlertIfRandomBodyIsEmpty";
        nano.addHandler(new LdapiHandler(path, Response.Status.OK, ""));
        HttpMessage msg = getHttpMessage(path + "?find=bar");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
        assertThat(httpMessagesSent, is(not(empty())));
    }

    @ParameterizedTest(name = "With Status {arguments}")
    @ValueSource(ints = {403, 404, 405, 500, 503})
    void shouldNotContinueIfOriginalMessageWasAnError(int status) throws IOException {
        // Given
        String path = "/shouldNotContinueIfOriginalMessageWasAnError";
        nano.addHandler(new LdapiHandler(path, Response.Status.OK, "different"));
        HttpMessage msg = this.getHttpMessage("GET", path + "?find=bar", DEFAULT_RESPONSE_STRING);
        msg.getResponseHeader().setStatusCode(status);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
        assertThat(httpMessagesSent, is(empty()));
    }

    @Test
    void shouldNotContinueIfPlaceboBodyIsTooSimilar() throws IOException {
        // Given
        String path = "/shouldNotContinueIfPlaceboBodyIsTooSimilar";
        nano.addHandler(new LdapiHandler(path, Response.Status.OK, DEFAULT_RESPONSE_STRING));
        HttpMessage msg = this.getHttpMessage("GET", path + "?find=bar", DEFAULT_RESPONSE_STRING);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
        assertThat(httpMessagesSent, is(not(empty())));
    }

    private static HttpMessage createMessage(String path) {
        try {

            HttpMessage msg = new HttpMessage(new URI("https://example.com" + path, true));
            msg.getResponseHeader().setStatusCode(HttpStatusCode.OK);
            return msg;
        } catch (URIException | HttpMalformedHeaderException | NullPointerException e) {
            // Ignore
        }
        return null;
    }

    private static class LdapiHandler extends NanoServerHandler {
        private final Response.IStatus status;
        private final String randBody;

        public LdapiHandler(String path, Response.IStatus status, String randBody) {
            super(path);
            this.status = status;
            this.randBody = randBody;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String pValue = getFirstParamValue(session, "find");

            if (pValue.length() == 21) {
                return newFixedLengthResponse(status, NanoHTTPD.MIME_HTML, randBody);
            }

            return newFixedLengthResponse(
                    NanoHTTPD.Response.Status.OK, NanoHTTPD.MIME_HTML, DEFAULT_RESPONSE_STRING);
        }
    }
}
