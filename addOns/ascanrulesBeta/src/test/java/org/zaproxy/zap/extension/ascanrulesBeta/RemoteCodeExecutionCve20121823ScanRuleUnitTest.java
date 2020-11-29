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
package org.zaproxy.zap.extension.ascanrulesBeta;

import static fi.iki.elonen.NanoHTTPD.newFixedLengthResponse;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.testutils.NanoServerHandler;

/** Unit test for {@link RemoteCodeExecutionCve20121823ScanRule}. */
public class RemoteCodeExecutionCve20121823ScanRuleUnitTest
        extends ActiveScannerTest<RemoteCodeExecutionCve20121823ScanRule> {

    @Override
    protected RemoteCodeExecutionCve20121823ScanRule createScanner() {
        return new RemoteCodeExecutionCve20121823ScanRule();
    }

    @Test
    public void shouldTargetPhpTech() throws Exception {
        // Given
        TechSet techSet = techSet(Tech.PHP);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(true)));
    }

    @Test
    public void shouldNotTargetNonPhpTechs() throws Exception {
        // Given
        TechSet techSet = techSetWithout(Tech.PHP);
        // When
        boolean targets = rule.targets(techSet);
        // Then
        assertThat(targets, is(equalTo(false)));
    }

    @Test
    public void shouldScanUrlsWithoutPath() throws Exception {
        // Given
        HttpMessage message = getHttpMessage("");
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(2));
    }

    @Test
    public void shouldScanUrlsWithEncodedCharsInPath() throws Exception {
        // Given
        String test = "/shouldScanUrlsWithEncodedCharsInPath/";
        nano.addHandler(
                new NanoServerHandler(test) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        consumeBody(session);
                        return newFixedLengthResponse("Nothing echoed...");
                    }
                });
        HttpMessage message = getHttpMessage(test + "%7B+%25%24");
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(2));
    }

    @Test
    public void shouldNotScanUrlsIfWinAndNixTechIsNotIncluded() throws Exception {
        // Given
        String test = "/shouldNotScanUrlsIfWinAndNixTechIsNotIncluded/";
        HttpMessage message = getHttpMessage(test);
        rule.init(message, parent);
        rule.setTechSet(techSetWithout(Tech.Linux, Tech.MacOS, Tech.Windows));
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(0));
    }

    @Test
    public void shouldNotAlertIfTheAttackIsNotEchoedInTheResponse() throws Exception {
        // Given
        String test = "/shouldNotAlertIfTheAttackIsNotEchoedInTheResponse/";
        nano.addHandler(
                new NanoServerHandler(test) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        consumeBody(session);
                        return newFixedLengthResponse("Nothing echoed...");
                    }
                });
        HttpMessage message = getHttpMessage(test);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldNotAlertEvenIfAttackResponseBodyHasBiggerSize() throws Exception {
        // Given
        String test = "/shouldNotAlertEvenIfResponseBodyHasBiggerSize/";
        nano.addHandler(
                new NanoServerHandler(test) {

                    @Override
                    protected Response serve(IHTTPSession session) {
                        consumeBody(session);

                        StringBuilder strBuilder = new StringBuilder("Nothing echoed...\n");
                        for (int i = 0; i < 50; i++) {
                            strBuilder.append(" response content...\n");
                        }
                        return newFixedLengthResponse(strBuilder.toString());
                    }
                });
        HttpMessage message = getHttpMessage(test);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldAlertIfWindowsAttackWasSuccessful() throws Exception {
        // Given
        final String body =
                RemoteCodeExecutionCve20121823ScanRule.RANDOM_STRING
                        + "<html><body>X Y Z</body></html>";
        String test = "/shouldAlertIfWindowsAttackWasSuccessful/";
        nano.addHandler(new WinResponse(test, body));
        HttpMessage message = getHttpMessage(test);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo(body)));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("")));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(
                        equalTo(
                                "<?php exec('cmd.exe /C echo "
                                        + RemoteCodeExecutionCve20121823ScanRule.RANDOM_STRING
                                        + "',$colm);echo join(\"\n\",$colm);die();?>")));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo(body)));
    }

    @Test
    public void shouldNotDoWinAttackIfWinTechIsNotIncluded() throws Exception {
        // Given
        final String body =
                RemoteCodeExecutionCve20121823ScanRule.RANDOM_STRING
                        + "<html><body>X Y Z</body></html>";
        String test = "/shouldNotDoWinAttackIfWinTechIsNotIncluded/";
        nano.addHandler(new WinResponse(test, body));
        HttpMessage message = getHttpMessage(test);
        rule.init(message, parent);
        rule.setTechSet(techSetWithout(Tech.Windows));
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertThat(httpMessagesSent, hasSize(1)); // Nix attack
    }

    @Test
    public void shouldAlertIfNixAttackWasSuccessful() throws Exception {
        // Given
        final String body =
                RemoteCodeExecutionCve20121823ScanRule.RANDOM_STRING
                        + "<html><body>X Y Z</body></html>";
        String test = "/shouldAlertIfNixAttackWasSuccessful/";
        nano.addHandler(new NixResponse(test, body));
        HttpMessage message = getHttpMessage(test);
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo(body)));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("")));
        assertThat(
                alertsRaised.get(0).getAttack(),
                is(
                        equalTo(
                                "<?php exec('echo "
                                        + RemoteCodeExecutionCve20121823ScanRule.RANDOM_STRING
                                        + "',$colm);echo join(\"\n\",$colm);die();?>")));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo(body)));
    }

    @Test
    public void shouldNotDoNixAttackIfNixTechsAreNotIncluded() throws Exception {
        // Given
        String test = "/shouldNotDoNixAttackIfNixTechsAreNotIncluded/";
        nano.addHandler(
                new NixResponse(
                        test,
                        RemoteCodeExecutionCve20121823ScanRule.RANDOM_STRING
                                + "<html><body>X Y Z</body></html>"));
        HttpMessage message = getHttpMessage(test);
        rule.init(message, parent);
        rule.setTechSet(techSetWithout(Tech.Linux, Tech.MacOS));
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
        assertThat(httpMessagesSent, hasSize(1)); // Win attack
    }

    private abstract static class RceResponse extends NanoServerHandler {

        private final String body;

        public RceResponse(String name, String body) {
            super(name);
            this.body = body;
        }

        @Override
        public Response serve(IHTTPSession session) {
            if (isAttackSuccessful(getBody(session))) {
                return newFixedLengthResponse(body);
            }
            return newFixedLengthResponse("Nothing echoed...");
        }

        protected abstract boolean isAttackSuccessful(String requestBody);
    }

    private static class WinResponse extends RceResponse {

        public WinResponse(String name, String body) {
            super(name, body);
        }

        @Override
        protected boolean isAttackSuccessful(String requestBody) {
            return requestBody.startsWith("<?php exec('cmd.exe");
        }
    }

    private static class NixResponse extends RceResponse {

        public NixResponse(String name, String body) {
            super(name, body);
        }

        @Override
        protected boolean isAttackSuccessful(String requestBody) {
            return requestBody.startsWith("<?php exec('echo");
        }
    }
}
