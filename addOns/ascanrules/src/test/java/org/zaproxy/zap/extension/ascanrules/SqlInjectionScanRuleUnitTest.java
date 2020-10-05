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
package org.zaproxy.zap.extension.ascanrules;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link SqlInjectionScanRule}. */
public class SqlInjectionScanRuleUnitTest extends ActiveScannerTest<SqlInjectionScanRule> {

    @Override
    protected int getRecommendMaxNumberMessagesPerParam(AttackStrength strength) {
        int recommendMax = super.getRecommendMaxNumberMessagesPerParam(strength);
        switch (strength) {
            case LOW:
                return recommendMax + 1;
            case MEDIUM:
            default:
                return recommendMax + 14;
            case HIGH:
                return recommendMax + 22;
            case INSANE:
                return recommendMax + 5;
        }
    }

    @Override
    protected SqlInjectionScanRule createScanner() {
        return new SqlInjectionScanRule();
    }

    @Test
    public void shouldTargetDbTech() {
        // Given
        TechSet techSet = techSet(Tech.Db);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    public void shouldTargetDbChildTechs() {
        // Given
        TechSet techSet = techSet(techsOf(Tech.Db));
        techSet.exclude(Tech.Db);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    public void shouldTargetDbChildTechsWithNonBuiltInTechInstances() {
        // Given
        TechSet techSet = techSet(new Tech(new Tech("Db"), "SomeDb"));
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    public void shouldNotTargetNonDbTechs() {
        // Given
        TechSet techSet = techSetWithout(techsOf(Tech.Db));
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test
    public void shouldAlertIfSumExpressionsAreSuccessful() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler("/", param, ExpressionBasedHandler.Expression.SUM));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.SUM.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo(param)));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo(ExpressionBasedHandler.Expression.SUM.baseExpression)));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    public void shouldAlertIfSumExpressionsAreSuccessfulAndReflectedInResponse() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler("/", param, ExpressionBasedHandler.Expression.SUM) {

                    @Override
                    protected String getContent(String value) {
                        return super.getContent(value) + ": " + value;
                    }
                });
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.SUM.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo(param)));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo(ExpressionBasedHandler.Expression.SUM.baseExpression)));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    public void shouldNotAlertIfSumConfirmationExpressionIsNotSuccessful() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler(
                        "/", param, ExpressionBasedHandler.Expression.SUM, true));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.SUM.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldNotAlertIfSumConfirmationExpressionIsNotSuccessfulAndIsReflectedInResponse()
            throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler(
                        "/",
                        param,
                        ExpressionBasedHandler.Expression.SUM,
                        true,
                        ExpressionBasedHandler.Expression.SUM.confirmationExpression));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.SUM.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldAlertIfMultExpressionsAreSuccessful() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler("/", param, ExpressionBasedHandler.Expression.MULT));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.MULT.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo(param)));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo(ExpressionBasedHandler.Expression.MULT.baseExpression)));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    public void shouldAlertIfMultExpressionsAreSuccessfulAndReflectedInResponse() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler("/", param, ExpressionBasedHandler.Expression.MULT) {

                    @Override
                    protected String getContent(String value) {
                        return super.getContent(value) + ": " + value;
                    }
                });
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.MULT.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo(param)));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(equalTo(ExpressionBasedHandler.Expression.MULT.baseExpression)));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    public void shouldNotAlertIfMultConfirmationExpressionIsNotSuccessful() throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler(
                        "/", param, ExpressionBasedHandler.Expression.MULT, true));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.MULT.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldNotAlertIfMultConfirmationExpressionIsNotSuccessfulAndReflectedInResponse()
            throws Exception {
        // Given
        String param = "id";
        nano.addHandler(
                new ExpressionBasedHandler(
                        "/",
                        param,
                        ExpressionBasedHandler.Expression.MULT,
                        true,
                        ExpressionBasedHandler.Expression.MULT.confirmationExpression));
        rule.init(
                getHttpMessage("/?" + param + "=" + ExpressionBasedHandler.Expression.MULT.value),
                parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    private static class ExpressionBasedHandler extends NanoServerHandler {

        public enum Expression {
            SUM("1", "3-2", "4-2"),
            MULT("1", "2/2", "4/2");

            private final String value;
            private final String baseExpression;
            private final String confirmationExpression;

            Expression(String value, String expression, String confirmationExpression) {
                this.value = value;
                this.baseExpression = expression;
                this.confirmationExpression = confirmationExpression;
            }
        }

        private final String param;
        private final Expression expression;
        private final boolean confirmationFails;
        private String contentAddition = "";

        public ExpressionBasedHandler(String path, String param, Expression expression) {
            this(path, param, expression, false);
        }

        public ExpressionBasedHandler(
                String path, String param, Expression expression, boolean confirmationFails) {
            super(path);

            this.param = param;
            this.expression = expression;
            this.confirmationFails = confirmationFails;
        }

        public ExpressionBasedHandler(
                String parth,
                String param,
                Expression expression,
                boolean confirmationFails,
                String contentAddition) {
            this(parth, param, expression, confirmationFails);
            this.contentAddition = contentAddition;
        }

        @Override
        protected Response serve(IHTTPSession session) {
            String value = getFirstParamValue(session, param);
            if (isValidValue(value)) {
                return newFixedLengthResponse(
                        Response.Status.OK, NanoHTTPD.MIME_HTML, getContent(value));
            }
            return newFixedLengthResponse(
                    Response.Status.NOT_FOUND, NanoHTTPD.MIME_HTML, "404 Not Found");
        }

        private boolean isValidValue(String value) {
            if (confirmationFails && expression.confirmationExpression.equals(value)) {
                return true;
            }
            return expression.value.equals(value) || expression.baseExpression.equals(value);
        }

        protected String getContent(String value) {
            return "Some Content " + contentAddition;
        }
    }
}
