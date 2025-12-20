/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.extension.graaljs.GraalJsActiveScriptScanRuleTestUtils;
import org.zaproxy.zap.testutils.NanoServerHandler;

class SuspiciousInputTransformationScriptUnitTest extends GraalJsActiveScriptScanRuleTestUtils {
    @Override
    public Path getScriptPath() throws Exception {
        return Path.of(
                getClass()
                        .getResource("/scripts/scripts/active/SuspiciousInputTransformation.js")
                        .toURI());
    }

    @Test
    void shouldReturnExpectedMappings() {
        assertThat(rule.getId(), is(equalTo(100044)));
        assertThat(rule.getName(), is(equalTo("Suspicious Input Transformation")));
        assertThat(rule.getCategory(), is(equalTo(Category.INJECTION)));
        assertThat(rule.getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(rule.getCweId(), is(equalTo(20)));
        assertThat(rule.getWascId(), is(equalTo(20)));
        assertThat(
                rule.getAlertTags().keySet(),
                containsInAnyOrder(
                        CommonAlertTag.OWASP_2021_A03_INJECTION.getTag(),
                        CommonAlertTag.OWASP_2017_A01_INJECTION.getTag(),
                        PolicyTag.PENTEST.getTag()));
        assertThat(rule.getStatus(), is(equalTo(AddOn.Status.alpha)));
    }

    @Test
    void shouldGetExampleAlerts() {
        // When
        var exampleAlerts = rule.getExampleAlerts();
        // Then
        assertThat(exampleAlerts, hasSize(10));
        Alert alert = exampleAlerts.get(0);
        assertThat(alert.getPluginId(), is(equalTo(100044)));
        assertThat(alert.getName(), containsString("Suspicious Input Transformation"));
        assertThat(alert.getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alert.getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alert.getCweId(), is(equalTo(20)));
        assertThat(alert.getWascId(), is(equalTo(20)));
        assertThat(
                alert.getTags().keySet(),
                containsInAnyOrder(
                        CommonAlertTag.OWASP_2021_A03_INJECTION.getTag(),
                        CommonAlertTag.OWASP_2017_A01_INJECTION.getTag(),
                        PolicyTag.PENTEST.getTag(),
                        "CWE-20"));
        // Alert refs checked in ScanRuleTests#shouldHaveExpectedAlertRefsInExampleAlerts
    }

    @Test
    void shouldRaiseAlertOnQuoteConsumption() throws Exception {
        // Given
        String path = "/quoteConsumption";
        nano.addHandler(new TransformationHandler(path));
        HttpMessage msg = getHttpMessage(path + "?param=value");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getName(), containsString("Quote Consumption"));
        assertThat(alert.getAlertRef(), is(equalTo("100044-1")));
        assertThat(alert.getParam(), is(equalTo("param")));
    }

    @Test
    void shouldRaiseAlertOnArithmeticEvaluation() throws Exception {
        // Given
        String path = "/arithmeticEvaluation";
        nano.addHandler(new TransformationHandler(path));
        HttpMessage msg = getHttpMessage(path + "?param=value");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getName(), containsString("Arithmetic Evaluation"));
        assertThat(alert.getAlertRef(), is(equalTo("100044-2")));
        assertThat(alert.getParam(), is(equalTo("param")));
    }

    @Test
    void shouldRaiseAlertOnExpressionEvaluation() throws Exception {
        // Given
        String path = "/expressionEvaluation";
        nano.addHandler(new TransformationHandler(path));
        HttpMessage msg = getHttpMessage(path + "?param=value");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getName(), containsString("Expression Evaluation"));
        assertThat(alert.getAlertRef(), is(equalTo("100044-3")));
        assertThat(alert.getParam(), is(equalTo("param")));
    }

    @Test
    void shouldRaiseAlertOnTemplateEvaluation() throws Exception {
        // Given
        String path = "/templateEvaluation";
        nano.addHandler(new TransformationHandler(path));
        HttpMessage msg = getHttpMessage(path + "?param=value");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getName(), containsString("Template Evaluation"));
        assertThat(alert.getAlertRef(), is(equalTo("100044-4")));
        assertThat(alert.getParam(), is(equalTo("param")));
    }

    @Test
    void shouldRaiseAlertOnElEvaluation() throws Exception {
        // Given
        String path = "/elEvaluation";
        nano.addHandler(new TransformationHandler(path));
        HttpMessage msg = getHttpMessage(path + "?param=value");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getName(), containsString("EL Evaluation"));
        assertThat(alert.getAlertRef(), is(equalTo("100044-5")));
        assertThat(alert.getParam(), is(equalTo("param")));
    }

    @Test
    void shouldRaiseAlertOnUnicodeNormalisation() throws Exception {
        // Given
        String path = "/unicodeNormalisation";
        nano.addHandler(new TransformationHandler(path));
        HttpMessage msg = getHttpMessage(path + "?param=value");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getName(), containsString("Unicode Normalisation"));
        assertThat(alert.getAlertRef(), is(equalTo("100044-6")));
        assertThat(alert.getParam(), is(equalTo("param")));
    }

    @Test
    void shouldRaiseAlertOnUrlDecodingError() throws Exception {
        // Given
        String path = "/urlDecodingError";
        nano.addHandler(new TransformationHandler(path));
        HttpMessage msg = getHttpMessage(path + "?param=value");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getName(), containsString("URL Decoding Error"));
        assertThat(alert.getAlertRef(), is(equalTo("100044-7")));
        assertThat(alert.getParam(), is(equalTo("param")));
    }

    @Test
    void shouldRaiseAlertOnUnicodeByteTruncation() throws Exception {
        // Given
        String path = "/unicodeByteTruncation";
        nano.addHandler(new TransformationHandler(path));
        HttpMessage msg = getHttpMessage(path + "?param=value");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getName(), containsString("Unicode Byte Truncation"));
        assertThat(alert.getAlertRef(), is(equalTo("100044-8")));
        assertThat(alert.getParam(), is(equalTo("param")));
    }

    @Test
    void shouldRaiseAlertOnUnicodeCaseConversion() throws Exception {
        // Given
        String path = "/unicodeCaseConversion";
        nano.addHandler(new TransformationHandler(path));
        HttpMessage msg = getHttpMessage(path + "?param=value");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getName(), containsString("Unicode Case Conversion"));
        assertThat(alert.getAlertRef(), is(equalTo("100044-9")));
        assertThat(alert.getParam(), is(equalTo("param")));
    }

    @Test
    void shouldRaiseAlertOnUnicodeCombiningDiacritic() throws Exception {
        // Given
        String path = "/unicodeCombiningDiacritic";
        nano.addHandler(new TransformationHandler(path));
        HttpMessage msg = getHttpMessage(path + "?param=value");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        Alert alert = alertsRaised.get(0);
        assertThat(alert.getName(), containsString("Unicode Combining Diacritic"));
        assertThat(alert.getAlertRef(), is(equalTo("100044-10")));
        assertThat(alert.getParam(), is(equalTo("param")));
    }

    @Test
    void shouldNotRaiseAlertWhenNoTransformation() throws Exception {
        // Given
        String path = "/noTransformation";
        nano.addHandler(new TransformationHandler(path));
        HttpMessage msg = getHttpMessage(path + "?param=value");
        rule.init(msg, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, is(empty()));
    }

    private static class TransformationHandler extends NanoServerHandler {
        private static final String DEFAULT_RESPONSE_STRING = "<html><body></body></html>";

        public TransformationHandler(String path) {
            super(path);
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String paramValue = getFirstParamValue(session, "param");
            String path = session.getUri();

            return handleQuoteConsumption(path, paramValue)
                    .or(() -> handleArithmeticEvaluation(path, paramValue))
                    .or(() -> handleExpressionEvaluation(path, paramValue))
                    .or(() -> handleTemplateEvaluation(path, paramValue))
                    .or(() -> handleUnicodeNormalisation(path, paramValue))
                    .or(() -> handleElEvaluation(path, paramValue))
                    .or(() -> handleUrlDecodingError(path, paramValue))
                    .or(() -> handleUnicodeByteTruncation(path, paramValue))
                    .or(() -> handleUnicodeCaseConversion(path, paramValue))
                    .or(() -> handleUnicodeCombiningDiacritic(path, paramValue))
                    .orElseGet(
                            () ->
                                    NanoHTTPD.newFixedLengthResponse(
                                            Response.Status.OK,
                                            NanoHTTPD.MIME_HTML,
                                            DEFAULT_RESPONSE_STRING));
        }

        private Optional<Response> handleQuoteConsumption(String path, String paramValue) {
            if (path.equals("/quoteConsumption") && paramValue.contains("''")) {
                String transformed = paramValue.replace("''", "'");
                return Optional.of(createSuccessResponse(transformed));
            }
            return Optional.empty();
        }

        private Optional<Response> handleArithmeticEvaluation(String path, String paramValue) {
            if (path.equals("/arithmeticEvaluation") && paramValue.contains("*")) {
                return evaluateArithmetic(paramValue);
            }
            return Optional.empty();
        }

        private Optional<Response> handleExpressionEvaluation(String path, String paramValue) {
            if (path.equals("/expressionEvaluation")
                    && paramValue.startsWith("${")
                    && paramValue.endsWith("}")) {
                String expression = paramValue.substring(2, paramValue.length() - 1);
                return evaluateArithmetic(expression);
            }
            return Optional.empty();
        }

        private Optional<Response> handleTemplateEvaluation(String path, String paramValue) {
            if (path.equals("/templateEvaluation")
                    && paramValue.startsWith("@(")
                    && paramValue.endsWith(")")) {
                String expression = paramValue.substring(2, paramValue.length() - 1);
                return evaluateArithmetic(expression);
            }
            return Optional.empty();
        }

        private Optional<Response> handleUnicodeNormalisation(String path, String paramValue) {
            if (path.equals("/unicodeNormalisation") && paramValue.contains("\u212a")) {
                String transformed = paramValue.replace("\u212a", "K");
                return Optional.of(createSuccessResponse(transformed));
            }
            return Optional.empty();
        }

        private Optional<Response> handleElEvaluation(String path, String paramValue) {
            if (path.equals("/elEvaluation")
                    && paramValue.startsWith("%{")
                    && paramValue.endsWith("}")) {
                String expression = paramValue.substring(2, paramValue.length() - 1);
                return evaluateArithmetic(expression);
            }
            return Optional.empty();
        }

        private Optional<Response> handleUrlDecodingError(String path, String paramValue) {
            if (path.equals("/urlDecodingError") && paramValue.contains("\u0391")) {
                String transformed = paramValue.replace("\u0391", "N\u0011");
                return Optional.of(createSuccessResponse(transformed));
            }
            return Optional.empty();
        }

        private Optional<Response> handleUnicodeByteTruncation(String path, String paramValue) {
            if (path.equals("/unicodeByteTruncation") && paramValue.contains("\uCF7B")) {
                String transformed = paramValue.replace("\uCF7B", "{");
                return Optional.of(createSuccessResponse(transformed));
            }
            return Optional.empty();
        }

        private Optional<Response> handleUnicodeCaseConversion(String path, String paramValue) {
            if (path.equals("/unicodeCaseConversion") && paramValue.contains("\u0131")) {
                String transformed = paramValue.replace("\u0131", "I");
                return Optional.of(createSuccessResponse(transformed));
            }
            return Optional.empty();
        }

        private Optional<Response> handleUnicodeCombiningDiacritic(String path, String paramValue) {
            if (path.equals("/unicodeCombiningDiacritic") && paramValue.contains("\u0338")) {
                String transformed = paramValue.replace("\u0338", "\u226F");
                return Optional.of(createSuccessResponse(transformed));
            }
            return Optional.empty();
        }

        private Optional<Response> evaluateArithmetic(String expression) {
            if (expression.contains("*")) {
                String[] parts = expression.split("\\*");
                if (parts.length == 2) {
                    try {
                        int x = Integer.parseInt(parts[0]);
                        int y = Integer.parseInt(parts[1]);
                        return Optional.of(createSuccessResponse(String.valueOf(x * y)));
                    } catch (NumberFormatException e) {
                        // Ignore
                    }
                }
            }
            return Optional.empty();
        }

        private Response createSuccessResponse(String content) {
            return NanoHTTPD.newFixedLengthResponse(
                    Response.Status.OK, NanoHTTPD.MIME_HTML, content);
        }
    }
}
