/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP development team
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
package org.zaproxy.zap.extension.ascanrules;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.Assert.assertThat;

import org.junit.Test;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;

/**
 * Unit test for {@link TestPathTraversal}.
 */
public class TestPathTraversalUnitTest extends ActiveScannerTest<TestPathTraversal> {

    @Override
    protected TestPathTraversal createScanner() {
        TestPathTraversal scanner = new TestPathTraversal();
        scanner.setConfig(new ZapXmlConfiguration());
        return scanner;
    }

    @Test
    public void shouldSendReasonableNumberOfMessagesInLowStrength() throws Exception {
        // Given
        rule.setAttackStrength(Plugin.AttackStrength.LOW);
        rule.init(getHttpMessage("?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(lessThanOrEqualTo(NUMBER_MSGS_ATTACK_STRENGTH_LOW + 4)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldSendReasonableNumberOfMessagesInMediumStrength() throws Exception {
        // Given
        rule.setAttackStrength(Plugin.AttackStrength.MEDIUM);
        rule.init(getHttpMessage("?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(lessThanOrEqualTo(NUMBER_MSGS_ATTACK_STRENGTH_MEDIUM + 6)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldSendReasonableNumberOfMessagesInDefaultStrength() throws Exception {
        // Given
        rule.setAttackStrength(Plugin.AttackStrength.DEFAULT); // Same as MEDIUM.
        rule.init(getHttpMessage("?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(lessThanOrEqualTo(NUMBER_MSGS_ATTACK_STRENGTH_MEDIUM + 6)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldSendReasonableNumberOfMessagesInHighStrength() throws Exception {
        // Given
        rule.setAttackStrength(Plugin.AttackStrength.HIGH);
        rule.init(getHttpMessage("?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(lessThanOrEqualTo(NUMBER_MSGS_ATTACK_STRENGTH_HIGH + 7)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldSendReasonableNumberOfMessagesInInsaneStrength() throws Exception {
        // Given
        rule.setAttackStrength(Plugin.AttackStrength.INSANE);
        rule.init(getHttpMessage("?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(lessThanOrEqualTo(75))); // No recommendation, use an arbitrary value.
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldNotAlertIfAttackResponseDoesNotListDirectories() throws Exception {
        // Given
        rule.init(getHttpMessage("/?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(0));
    }

    @Test
    public void shouldAlertIfAttackResponseListsWindowsDirectories() throws Exception {
        // Given
        nano.addHandler(new ListWinDirsOnAttack("/", "p", "c:/"));
        rule.init(getHttpMessage("/?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("Windows")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("p")));
        assertThat(alertsRaised.get(0).getAttack(), is(equalTo("c:/")));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    @Test
    public void shouldAlertIfAttackResponseListsLinuxDirectories() throws Exception {
        // Given
        nano.addHandler(new ListLinuxDirsOnAttack("/", "p", "/"));
        rule.init(getHttpMessage("/?p=v"), parent);
        // When
        rule.scan();
        // Then
        assertThat(httpMessagesSent, hasSize(greaterThan(1)));
        assertThat(alertsRaised, hasSize(1));
        assertThat(alertsRaised.get(0).getEvidence(), is(equalTo("etc")));
        assertThat(alertsRaised.get(0).getParam(), is(equalTo("p")));
        assertThat(alertsRaised.get(0).getAttack(), is(equalTo("/")));
        assertThat(alertsRaised.get(0).getRisk(), is(equalTo(Alert.RISK_HIGH)));
        assertThat(alertsRaised.get(0).getConfidence(), is(equalTo(Alert.CONFIDENCE_MEDIUM)));
    }

    private static abstract class ListDirsOnAttack extends NanoServerHandler {

        private final String param;
        private final String attack;

        public ListDirsOnAttack(String path, String param, String attack) {
            super(path);

            this.param = param;
            this.attack = attack;
        }

        protected abstract String getDirs();

        @Override
        Response serve(IHTTPSession session) {
            String value = session.getParms().get(param);
            if (attack.equals(value)) {
                return new Response(Response.Status.OK, NanoHTTPD.MIME_HTML, getDirs());
            }
            return new Response(Response.Status.NOT_FOUND, NanoHTTPD.MIME_HTML, "404 Not Found");
        }
    }

    private static class ListWinDirsOnAttack extends ListDirsOnAttack {

        private static final String DIRS_LISTING = "<td><a href=\"Windows/\">Windows</a></td>"
                + "<td><a href=\"Program Files/\">Program Files</a></td>";

        public ListWinDirsOnAttack(String path, String param, String attack) {
            super(path, param, attack);
        }

        @Override
        protected String getDirs() {
            return DIRS_LISTING;
        }
    }

    private static class ListLinuxDirsOnAttack extends ListDirsOnAttack {

        private static final String DIRS_LISTING = "<td><a href=\"/bin/\">bin</a></td>" + "<td><a href=\"/etc/\">etc</a></td>"
                + "<td><a href=\"/boot/\">boot</a></td>";

        public ListLinuxDirsOnAttack(String path, String param, String attack) {
            super(path, param, attack);
        }

        @Override
        protected String getDirs() {
            return DIRS_LISTING;
        }
    }
}