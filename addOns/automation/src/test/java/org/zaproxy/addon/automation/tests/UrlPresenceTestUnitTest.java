/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.automation.tests;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

import org.apache.commons.httpclient.URI;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.SiteMap;
import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.zap.testutils.TestUtils;

class UrlPresenceTestUnitTest extends TestUtils {

    private static final String EXPECTED_URL = "http://example.com/";

    private AutomationProgress progress;
    private AutomationJob job;

    @BeforeAll
    static void beforeAll() {
        mockMessages(new ExtensionAutomation());
    }

    @BeforeEach
    void setup() throws Exception {
        progress = new AutomationProgress();
        job = mock(AutomationJob.class);
        AutomationEnvironment env = new AutomationEnvironment(progress);
        given(job.getEnv()).willReturn(env);

        Model model = mock(Model.class);
        Model.setSingletonForTesting(model);

        Session session = mock(Session.class);
        given(model.getSession()).willReturn(session);

        SiteMap siteMap = mock(SiteMap.class);
        given(session.getSiteTree()).willReturn(siteMap);

        SiteNode siteNode = mock(SiteNode.class);
        given(siteMap.findNode(any(URI.class))).willReturn(siteNode);

        HistoryReference historyReference = mock(HistoryReference.class);
        given(siteNode.getHistoryReference()).willReturn(historyReference);

        HttpMessage msg = new HttpMessage();
        msg.setRequestHeader("GET " + EXPECTED_URL + " HTTP/1.1");
        msg.setResponseBody(
                "<html><head><link href=\"https://site53.example.net/style.css\"></head><body></body></html>");
        given(historyReference.getHttpMessage()).willReturn(msg);
    }

    @Test
    void shouldPassTestWithOperatorOrIfSpecifiedConditionIsSatisfied() {
        String operator = "or";
        String name = "test";
        String onFail = "warn";
        String requestHeaderRegex = "";
        String requestBodyRegex = "";
        String responseHeaderRegex = "";
        String responseBodyRegex = "https://site53";

        UrlPresenceTest test =
                new UrlPresenceTest(
                        name,
                        onFail,
                        operator,
                        EXPECTED_URL,
                        requestHeaderRegex,
                        requestBodyRegex,
                        responseHeaderRegex,
                        responseBodyRegex,
                        job,
                        progress);

        boolean run = test.runTest(progress);
        test.logToProgress(progress);
        assertThat(run, is(true));
        assertThat(test.getName(), is(name));
        assertThat(test.getTestType(), is(UrlPresenceTest.TEST_TYPE));
        assertThat(test.hasPassed(), is(true));
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.hasWarnings(), is(false)); // no warnings
    }

    @Test
    void shouldPassTestWithOperatorAndIfSpecifiedConditionIsSatisfied() throws Exception {
        String operator = "and";
        String name = "test";
        String onFail = "error";
        String requestHeaderRegex = "";
        String requestBodyRegex = "";
        String responseHeaderRegex = "";
        String responseBodyRegex = "site";

        UrlPresenceTest test =
                new UrlPresenceTest(
                        name,
                        onFail,
                        operator,
                        EXPECTED_URL,
                        requestHeaderRegex,
                        requestBodyRegex,
                        responseHeaderRegex,
                        responseBodyRegex,
                        job,
                        progress);

        boolean run = test.runTest(progress);
        test.logToProgress(progress);
        assertThat(run, is(true));
        assertThat(test.getName(), is(name));
        assertThat(test.getTestType(), is(UrlPresenceTest.TEST_TYPE));
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.hasWarnings(), is(false));
        assertThat(test.hasPassed(), is(true));
    }

    @Test
    void shouldFailTestWithOperatorOrIfNoneOfTheSpecifiedConditionIsSatisfied() throws Exception {
        String operator = "or";
        String name = "test";
        String onFail = "warn";
        String requestHeaderRegex = "^freshpotatoes$";
        String requestBodyRegex = "";
        String responseHeaderRegex = "";
        String responseBodyRegex = "^<link href=\"https://site73\"/>$";

        UrlPresenceTest test =
                new UrlPresenceTest(
                        name,
                        onFail,
                        operator,
                        EXPECTED_URL,
                        requestHeaderRegex,
                        requestBodyRegex,
                        responseHeaderRegex,
                        responseBodyRegex,
                        job,
                        progress);

        boolean run = test.runTest(progress);
        test.logToProgress(progress);

        assertThat(run, is(false));
        assertThat(test.getName(), is(name));
        assertThat(test.getTestType(), is(UrlPresenceTest.TEST_TYPE));
        assertThat(test.hasPassed(), is(false));
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.hasWarnings(), is(true));
    }

    @Test
    void shouldFailWithOperatorAndIfSpecifiedConditionIsNotSatisfied() throws Exception {
        String operator = "and";
        String name = "test";
        String onFail = "warn";
        String requestHeaderRegex = "^freshpotatoes$";
        String requestBodyRegex = "";
        String responseHeaderRegex = "";
        String responseBodyRegex = "https://site73";

        UrlPresenceTest test =
                new UrlPresenceTest(
                        name,
                        onFail,
                        operator,
                        EXPECTED_URL,
                        requestHeaderRegex,
                        requestBodyRegex,
                        responseHeaderRegex,
                        responseBodyRegex,
                        job,
                        progress);

        boolean run = test.runTest(progress);
        test.logToProgress(progress);

        assertThat(run, is(false));
        assertThat(test.getName(), is(name));
        assertThat(test.getTestType(), is(UrlPresenceTest.TEST_TYPE));
        assertThat(test.hasPassed(), is(false));

        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.hasWarnings(), is(true));
    }

    @Test
    void shouldFailOnInvalidUrlParameter() throws Exception {
        String url = "http://notexample.com/";
        String name = "test";
        String onFail = "warn";
        String requestHeaderRegex = "^freshpotatoes$";
        String requestBodyRegex = "";
        String responseHeaderRegex = "";
        String responseBodyRegex = "";
        String operator = "or";

        UrlPresenceTest test =
                new UrlPresenceTest(
                        name,
                        onFail,
                        operator,
                        url,
                        requestHeaderRegex,
                        requestBodyRegex,
                        responseHeaderRegex,
                        responseBodyRegex,
                        job,
                        progress);

        boolean hasrun = test.hasRun();
        test.logToProgress(progress);
        assertThat(hasrun, is(false));
        assertThat(test.getName(), is(name));
        assertThat(test.getTestType(), is(UrlPresenceTest.TEST_TYPE));
        assertThat(test.hasPassed(), is(false));
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.hasWarnings(), is(true));
    }

    @Test
    void shouldFailOnBadOperator() throws Exception {
        String name = "test";
        String onFail = "warn";
        String operator = "bad";
        String requestHeaderRegex = "^freshpotatoes$";
        String requestBodyRegex = "";
        String responseHeaderRegex = "";
        String responseBodyRegex = "";

        UrlPresenceTest test =
                new UrlPresenceTest(
                        name,
                        onFail,
                        operator,
                        EXPECTED_URL,
                        requestHeaderRegex,
                        requestBodyRegex,
                        responseHeaderRegex,
                        responseBodyRegex,
                        job,
                        progress);

        boolean run = test.runTest(progress);
        test.logToProgress(progress);

        assertThat(run, is(false));
        assertThat(test.getName(), is(name));
        assertThat(test.getTestType(), is(UrlPresenceTest.TEST_TYPE));
        assertThat(test.hasPassed(), is(false));

        assertThat(progress.hasWarnings(), is(true));
    }

    @Test
    void shouldPassIfNoRegexesAreGivenButUrlExists() throws Exception {
        String name = "test";
        String onFail = "warn";
        String operator = "or";
        String requestHeaderRegex = "";
        String requestBodyRegex = "";
        String responseHeaderRegex = "";
        String responseBodyRegex = "";
        UrlPresenceTest test =
                new UrlPresenceTest(
                        name,
                        onFail,
                        operator,
                        EXPECTED_URL,
                        requestHeaderRegex,
                        requestBodyRegex,
                        responseHeaderRegex,
                        responseBodyRegex,
                        job,
                        progress);

        boolean run = test.runTest(progress);
        test.logToProgress(progress);
        assertThat(run, is(true));
        assertThat(test.getName(), is(name));
        assertThat(test.getTestType(), is(UrlPresenceTest.TEST_TYPE));
        assertThat(test.hasPassed(), is(true));

        assertThat(progress.hasWarnings(), is(false));
    }

    @Test
    void shouldPassIfAnyOrConditionIsSatisfied() throws Exception {
        String name = "test";
        String onFail = "warn";
        String operator = "or";
        String requestHeaderRegex = "200";
        String requestBodyRegex = "";
        String responseHeaderRegex = "";
        String responseBodyRegex = "53.example";

        UrlPresenceTest test =
                new UrlPresenceTest(
                        name,
                        onFail,
                        operator,
                        EXPECTED_URL,
                        requestHeaderRegex,
                        requestBodyRegex,
                        responseHeaderRegex,
                        responseBodyRegex,
                        job,
                        progress);

        boolean run = test.runTest(progress);
        test.logToProgress(progress);

        assertThat(run, is(true));
        assertThat(test.getName(), is(name));
        assertThat(test.getTestType(), is(UrlPresenceTest.TEST_TYPE));
        assertThat(test.hasPassed(), is(true));
    }
}
