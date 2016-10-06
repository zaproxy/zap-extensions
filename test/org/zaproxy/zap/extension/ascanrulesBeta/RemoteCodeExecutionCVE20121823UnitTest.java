/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP development team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrulesBeta;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;

/**
 * Unit test for {@link RemoteCodeExecutionCVE20121823}.
 */
public class RemoteCodeExecutionCVE20121823UnitTest extends ActiveScannerTest {

    @Override
    protected RemoteCodeExecutionCVE20121823 createScanner() {
        return new RemoteCodeExecutionCVE20121823();
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
        String test = "shouldScanUrlsWithEncodedCharsInPath";
        nano.addHandler(new NanoServerHandler(test) {

            @Override
            Response serve(IHTTPSession session) {
                consumeBody(session);
                return new Response("Nothing echoed...");
            }
        });
        HttpMessage message = getHttpMessage("/" + test + "/%7B+%25%24");
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(2));
    }

    @Test
    public void shouldNotAlertIfTheAttackIsNotEchoedInTheResponse() throws Exception {
        // Given
        String test = "shouldNotAlertIfTheAttackIsNotEchoedInTheResponse";
        nano.addHandler(new NanoServerHandler(test) {

            @Override
            Response serve(IHTTPSession session) {
                consumeBody(session);
                return new Response("Nothing echoed...");
            }
        });
        HttpMessage message = getHttpMessage("/" + test + "/");
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldNotAlertEvenIfAttackResponseBodyHasBiggerSize() throws Exception {
        // Given
        String test = "shouldNotAlertEvenIfResponseBodyHasBiggerSize";
        nano.addHandler(new NanoServerHandler(test) {

            @Override
            Response serve(IHTTPSession session) {
                consumeBody(session);

                StringBuilder strBuilder = new StringBuilder("Nothing echoed...\n");
                for (int i = 0; i < 50; i++) {
                    strBuilder.append(" response content...\n");
                }
                return new Response(strBuilder.toString());
            }
        });
        HttpMessage message = getHttpMessage("/" + test + "/");
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldAlertIfWindowsAttackWasSuccessful() throws Exception {
        // Given
        final String body = RemoteCodeExecutionCVE20121823.RANDOM_STRING + "<html><body>X Y Z</body></html>";
        String test = "shouldAlertIfWindowsAttackWasSuccessful";
        nano.addHandler(new NanoServerHandler(test) {

            @Override
            Response serve(IHTTPSession session) {
                if (getBody(session).contains("cmd.exe")) {
                    return new Response(body);
                }
                return new Response("Nothing echoed...");
            }
        });
        HttpMessage message = getHttpMessage("/" + test + "/");
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo(body)));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getAttack(), is(
                equalTo("<?php exec('cmd.exe /C echo " + RemoteCodeExecutionCVE20121823.RANDOM_STRING
                        + "',$colm);echo join(\"\n\",$colm);die();?>")));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo(body)));
    }

    @Test
    public void shouldAlertIfNixAttackWasSuccessful() throws Exception {
        // Given
        final String body = RemoteCodeExecutionCVE20121823.RANDOM_STRING + "<html><body>X Y Z</body></html>";
        String test = "shouldAlertIfNixAttackWasSuccessful";
        nano.addHandler(new NanoServerHandler(test) {

            @Override
            Response serve(IHTTPSession session) {
                if (!getBody(session).contains("cmd.exe")) {
                    return new Response(body);
                }
                return new Response("Nothing echoed...");
            }
        });
        HttpMessage message = getHttpMessage("/" + test + "/");
        rule.init(message, parent);
        // When
        rule.scan();
        // Then
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo(body)));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("")));
        assertThat(alertsRaised.get(0).getAttack(), is(
                equalTo("<?php exec('echo " + RemoteCodeExecutionCVE20121823.RANDOM_STRING
                        + "',$colm);echo join(\"\n\",$colm);die();?>")));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
        assertThat(alertsRaised.get(0).getOtherInfo(), is(equalTo(body)));
    }

}
