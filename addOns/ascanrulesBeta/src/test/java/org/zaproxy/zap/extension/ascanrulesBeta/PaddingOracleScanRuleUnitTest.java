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
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import fi.iki.elonen.NanoHTTPD;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.testutils.NanoServerHandler;

class PaddingOracleScanRuleUnitTest extends ActiveScannerTest<PaddingOracleScanRule> {

    @Override
    protected PaddingOracleScanRule createScanner() {
        return new PaddingOracleScanRule();
    }

    static Stream<String> errorPatternsProvider() {
        return Stream.of(PaddingOracleScanRule.ERROR_PATTERNS);
    }

    @Test
    void shouldReturnExpectedMappings() {
        // Given / When
        int cwe = rule.getCweId();
        int wasc = rule.getWascId();
        Map<String, String> tags = rule.getAlertTags();
        // Then
        assertThat(cwe, is(equalTo(209)));
        assertThat(wasc, is(equalTo(20)));
        assertThat(tags.size(), is(equalTo(3)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2021_A02_CRYPO_FAIL.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.containsKey(CommonAlertTag.WSTG_V42_CRYP_02_PADDING_ORACLE.getTag()),
                is(equalTo(true)));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2021_A02_CRYPO_FAIL.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2021_A02_CRYPO_FAIL.getValue())));
        assertThat(
                tags.get(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getTag()),
                is(equalTo(CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG.getValue())));
        assertThat(
                tags.get(CommonAlertTag.WSTG_V42_CRYP_02_PADDING_ORACLE.getTag()),
                is(equalTo(CommonAlertTag.WSTG_V42_CRYP_02_PADDING_ORACLE.getValue())));
    }

    @ParameterizedTest
    @MethodSource("errorPatternsProvider")
    void shouldReportPaddingOracleForBase64Value(String errorPattern) throws Exception {
        assumeFalse(
                "runtime error".equals(errorPattern), "It's matched by 'runtime' error pattern.");

        // Given
        String test = "/shouldReportPaddingOracleForBase64Value/";
        String token = "0VMIb2LTBeKOxKV3Dhtt78AAJmajZbsuZ8pjOPJi2XpVRdWi2qjrSZ333DRl8HjD";
        nano.addHandler(
                new ServerHandler(
                        test,
                        injectedValue -> {
                            if (token.equals(injectedValue)) {
                                return newFixedLengthResponse("All ok.");
                            }
                            if ("0VMIb2LTBeKOxKV3Dhtt78AAJmajZbsuZ8pjOPJi2XpVRdWi2qjrSZ333DRl8HjC"
                                    .equals(injectedValue)) {
                                return newFixedLengthResponse(
                                        NanoHTTPD.Response.Status.INTERNAL_ERROR,
                                        NanoHTTPD.MIME_PLAINTEXT,
                                        "Something went wrong: " + errorPattern);
                            }
                            return newFixedLengthResponse("Unknown value.");
                        }));
        HttpMessage msg = getHttpMessage(test + "?field=" + token);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(2));
        assertThat(alertsRaised.get(1).getParam(), equalTo("field"));
        assertThat(alertsRaised.get(1).getEvidence(), is(equalTo(errorPattern)));
    }

    @ParameterizedTest
    @MethodSource("errorPatternsProvider")
    void shouldNotReportPaddingOracleForValidationFields(String errorPattern) throws Exception {
        // Given
        String test = "/shouldNotReportPaddingOracleForValidationFields/";
        String validationField = "0VMIb2LTBeKOxKV3Dhtt78AAJmajZbsuZ8pjOPJi2XpVRdWi2qjrSZ333DRl8HjD";
        nano.addHandler(
                new ServerHandler(
                        test,
                        injectedValue -> {
                            if (validationField.equals(injectedValue)) {
                                return newFixedLengthResponse("Verification passed.");
                            }
                            return newFixedLengthResponse(
                                    "Verification failed and here's an error pattern: "
                                            + errorPattern);
                        }));
        HttpMessage msg = getHttpMessage(test + "?field=" + validationField);
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    private static class ServerHandler extends NanoServerHandler {

        private final Function<String, NanoHTTPD.Response> responseHandler;

        public ServerHandler(String path, Function<String, NanoHTTPD.Response> responseHandler) {
            super(path);

            this.responseHandler = responseHandler;
        }

        @Override
        protected NanoHTTPD.Response serve(NanoHTTPD.IHTTPSession session) {
            return responseHandler.apply(getFirstParamValue(session, "field"));
        }
    }
}
