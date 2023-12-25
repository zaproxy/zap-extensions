/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.replacer.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.quality.Strictness;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.extension.replacer.ExtensionReplacer;
import org.zaproxy.zap.extension.replacer.ReplacerParam;
import org.zaproxy.zap.extension.replacer.ReplacerParamRule;
import org.zaproxy.zap.extension.replacer.ReplacerParamRule.MatchType;
import org.zaproxy.zap.extension.replacer.automation.ReplacerJob.RuleData;
import org.zaproxy.zap.testutils.TestUtils;

class ReplacerJobUnitTest extends TestUtils {

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionReplacer());
    }

    @Test
    void shouldReturnDefaultFields() {
        // Given / When
        ReplacerJob job = new ReplacerJob();

        // Then
        assertThat(job.getType(), is(equalTo("replacer")));
        assertThat(job.getName(), is(equalTo("replacer")));
        assertThat(job.getParameters(), is(notNullValue()));
        assertThat(job.getParameters().getDeleteAllRules(), is(nullValue()));
        assertThat(job.getData(), is(notNullValue()));
        assertThat(job.getData().getRules(), is(notNullValue()));
        assertThat(job.getData().getRules().size(), is(0));
        assertThat(job.getOrder(), is(equalTo(AutomationJob.Order.CONFIGS)));
        assertThat(job.getParamMethodObject(), is(nullValue()));
        assertThat(job.getParamMethodName(), is(nullValue()));
    }

    @Test
    void shouldVerifyWithNoData() {
        // Given
        ReplacerJob job = new ReplacerJob();
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(job.getRuleCount(), is(equalTo(0)));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldApplyParameterDeleteAllRules(boolean value) {
        // Given
        ReplacerJob job =
                createReplacerJob(
                        "parameters:\n" + "  deleteAllRules: " + value + "\n" + "rules: []");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(job.getData().getParameters().getDeleteAllRules(), is(equalTo(value)));
    }

    @Test
    void shouldApplyValidMinRule() {
        // Given
        ReplacerJob job =
                createReplacerJob(
                        "parameters:\n"
                                + "  deleteAllRules: false\n"
                                + "rules:\n"
                                + "  - matchType: resp_body_str\n"
                                + "    matchString: test");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(job.getRuleCount(), is(equalTo(1)));
        assertThat(job.getData().getRules().size(), is(equalTo(1)));
        assertThat(job.getData().getRules().get(0).getDescription(), is(nullValue()));
        assertThat(job.getData().getRules().get(0).getUrl(), is(nullValue()));
        assertThat(job.getData().getRules().get(0).getMatchType(), is(equalTo("resp_body_str")));
        assertThat(job.getData().getRules().get(0).isMatchRegex(), is(nullValue()));
        assertThat(job.getData().getRules().get(0).getReplacementString(), is(nullValue()));
        assertThat(job.getData().getRules().get(0).getTokenProcessing(), is(nullValue()));
        assertThat(job.getData().getRules().get(0).getInitiators(), is(nullValue()));
    }

    @Test
    void shouldApplyValidFullRule() {
        // Given
        ReplacerJob job =
                createReplacerJob(
                        "parameters:\n"
                                + "  deleteAllRules: false\n"
                                + "rules:\n"
                                + "  - description: desc\n"
                                + "    url: url\n"
                                + "    matchType: resp_body_str\n"
                                + "    matchString: test\n"
                                + "    matchRegex: true\n"
                                + "    replacementString: rep\n"
                                + "    tokenProcessing: false\n"
                                + "    initiators: [1, 2, 3]\n");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(job.getRuleCount(), is(equalTo(1)));
        assertThat(job.getData().getRules().size(), is(equalTo(1)));
        assertThat(job.getData().getRules().get(0).getDescription(), is("desc"));
        assertThat(job.getData().getRules().get(0).getUrl(), is("url"));
        assertThat(job.getData().getRules().get(0).getMatchType(), is(equalTo("resp_body_str")));
        assertThat(job.getData().getRules().get(0).getMatchString(), is(equalTo("test")));
        assertThat(job.getData().getRules().get(0).isMatchRegex(), is(true));
        assertThat(job.getData().getRules().get(0).getReplacementString(), is("rep"));
        assertThat(job.getData().getRules().get(0).getTokenProcessing(), is(false));
        assertThat(job.getData().getRules().get(0).getInitiators(), is(notNullValue()));
        assertThat(job.getData().getRules().get(0).getInitiators().length, is(3));
        assertThat(job.getData().getRules().get(0).getInitiators()[0], is(1));
        assertThat(job.getData().getRules().get(0).getInitiators()[1], is(2));
        assertThat(job.getData().getRules().get(0).getInitiators()[2], is(3));
    }

    @Test
    void shouldReportNoRules() {
        // Given
        ReplacerJob job = createReplacerJob("parameters:\n" + "  deleteAllRules: false");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0),
                is(equalTo("Job: replacer No rules element defined")));
    }

    @Test
    void shouldReportBadRules() {
        // Given
        ReplacerJob job =
                createReplacerJob(
                        "parameters:\n" + "  deleteAllRules: false\n" + "rules: not a list");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                is(equalTo("Job: replacer The rules element is not a list")));
    }

    @Test
    void shouldReportBadRule() {
        // Given
        ReplacerJob job =
                createReplacerJob("parameters:\n" + "  deleteAllRules: false\n" + "rules: [1, 2]");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0), is(equalTo("Job: replacer Invalid rule format: 1")));
    }

    @Test
    void shouldReportInvalidUrlRegex() {
        // Given
        ReplacerJob job =
                createReplacerJob(
                        "parameters:\n"
                                + "  deleteAllRules: false\n"
                                + "rules:\n"
                                + "  - matchType: resp_body_str\n"
                                + "    url: '*'\n"
                                + "    matchString: test");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("Job: replacer Invalid URL: *")));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldReportInvalidMatchType() {
        // Given
        ReplacerJob job =
                createReplacerJob(
                        "parameters:\n"
                                + "  deleteAllRules: false\n"
                                + "rules:\n"
                                + "  - matchType: blah\n"
                                + "    matchString: test");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                is(
                        equalTo(
                                "Invalid Match Type replacer - it should be one of [req_header, req_header_str, req_body_str, resp_header, resp_header_str, resp_body_str]")));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldReportBlankMatchString() {
        // Given
        ReplacerJob job =
                createReplacerJob(
                        "rules:\n" + "  - matchType: resp_body_str\n" + "    matchString: ");
        AutomationProgress progress = new AutomationProgress();

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                is(
                        equalTo(
                                "Job: replacer No matchString has been specified for one of the rules")));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @Test
    void shouldRemoveRules() {
        // Given
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionReplacer extRep =
                mock(ExtensionReplacer.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionReplacer.class)).willReturn(extRep);
        ReplacerParam params = mock(ReplacerParam.class);
        given(extRep.getParams()).willReturn(params);
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        ReplacerJob job =
                createReplacerJob("parameters:\n" + "  deleteAllRules: true\n" + "rules: []");
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);

        // When
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        verify(params).clearRules();
    }

    @Test
    void shouldAddRules() {
        // Given
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader =
                mock(ExtensionLoader.class, withSettings().strictness(Strictness.LENIENT));
        ExtensionReplacer extRep =
                mock(ExtensionReplacer.class, withSettings().strictness(Strictness.LENIENT));
        given(extensionLoader.getExtension(ExtensionReplacer.class)).willReturn(extRep);
        ReplacerParam params = mock(ReplacerParam.class);
        given(extRep.getParams()).willReturn(params);
        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);

        ReplacerJob job =
                createReplacerJob(
                        "rules: \n"
                                + "  - matchType: req_header_str\n"
                                + "    matchString: test1\n"
                                + "  - matchType: resp_body_str\n"
                                + "    matchString: test2");
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);

        // When
        job.verifyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        verify(params, times(2)).addRule(any());
    }

    @Test
    void shouldConvertDataToRule() {
        // Given
        RuleData data = new RuleData();
        data.setDescription("desc");
        data.setUrl("url");
        data.setMatchType("Resp_Header");
        data.setMatchString("match");
        data.setMatchRegex(true);
        data.setReplacementString("repl");
        data.setTokenProcessing(true);
        data.setInitiators(new Integer[] {2, 4, 6});

        AutomationProgress progress = new AutomationProgress();

        // When
        ReplacerParamRule rule = ReplacerJob.dataToReplacerRule(data, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(rule.getDescription(), is("desc"));
        assertThat(rule.getUrl(), is("url"));
        assertThat(rule.getMatchType(), is(MatchType.RESP_HEADER));
        assertThat(rule.getMatchString(), is("match"));
        assertThat(rule.isMatchRegex(), is(true));
        assertThat(rule.isTokenProcessingEnabled(), is(true));
        assertThat(rule.getInitiators(), is(notNullValue()));
        assertThat(rule.getInitiators().size(), is(3));
        assertThat(rule.getInitiators().get(0), is(2));
        assertThat(rule.getInitiators().get(1), is(4));
        assertThat(rule.getInitiators().get(2), is(6));
    }

    @Test
    void shouldReportBadMatchTypeWhenConvertingDataToRule() {
        // Given
        RuleData data = new RuleData();
        data.setMatchType("Resp_Header_xx");

        AutomationProgress progress = new AutomationProgress();

        // When
        ReplacerJob.dataToReplacerRule(data, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(
                progress.getErrors().get(0),
                is(
                        equalTo(
                                "Invalid Match Type RESP_HEADER_XX - it should be one of [req_header, req_header_str, req_body_str, resp_header, resp_header_str, resp_body_str]")));
    }

    @Test
    void shouldConvertRuleToData() {
        // Given
        List<Integer> initiators = new ArrayList<>();
        initiators.add(3);
        initiators.add(5);
        ReplacerParamRule rule =
                new ReplacerParamRule(
                        "desc",
                        "url",
                        MatchType.RESP_HEADER_STR,
                        "match",
                        true,
                        "replace",
                        initiators,
                        true,
                        true);

        RuleData data = new RuleData();

        // When
        ReplacerJob.replacerRuleToData(rule, data);

        // Then
        assertThat(data.getDescription(), is("desc"));
        assertThat(data.getUrl(), is("url"));
        assertThat(data.getMatchType(), is("resp_header_str"));
        assertThat(data.getMatchString(), is("match"));
        assertThat(data.isMatchRegex(), is(true));
        assertThat(data.getReplacementString(), is("replace"));
        assertThat(data.getTokenProcessing(), is(true));
        assertThat(data.getInitiators(), is(notNullValue()));
        assertThat(data.getInitiators().length, is(2));
        assertThat(data.getInitiators()[0], is(3));
        assertThat(data.getInitiators()[1], is(5));
    }

    @Test
    void shouldGetMinTemplateData() {
        // Given
        ReplacerJob job = new ReplacerJob();

        // When
        String template = job.getTemplateDataMin();

        // Then
        assertThat(
                template,
                is(
                        "  - type: \"replacer\"                   # Replacer rules\n"
                                + "    parameters:\n"
                                + "      deleteAllRules:                  # Boolean, if true then will delete all existing replacer rules, default false\n"
                                + "    rules:                             # A list of replacer rules\n"
                                + "      - description:                   # String, the name of the rule\n"
                                + "        url:                           # String, a regex which will be used to match URLs, if empty then it will match all\n"
                                + "        matchType:                     # String, one of req_header, req_header_str, req_body_str, resp_header, resp_header_str, resp_body_str\n"
                                + "        matchString:                   # String, will be used to identify what should be replaced\n"
                                + "        matchRegex:                    # Boolean, if set then the matchString will be treated as a regex, default false\n"
                                + "        replacementString:             # String, the new string that will replace the specified selection\n"));
    }

    @Test
    void shouldGetMaxTemplateData() {
        // Given
        ReplacerJob job = new ReplacerJob();

        // When
        String template = job.getTemplateDataMax();

        // Then
        assertThat(
                template,
                is(
                        "  - type: \"replacer\"                   # Replacer rules\n"
                                + "    parameters:\n"
                                + "      deleteAllRules:                  # Boolean, if true then will delete all existing replacer rules, default false\n"
                                + "    rules:                             # A list of replacer rules\n"
                                + "      - description:                   # String, the name of the rule\n"
                                + "        url:                           # String, a regex which will be used to match URLs, if empty then it will match all\n"
                                + "        matchType:                     # String, one of req_header, req_header_str, req_body_str, resp_header, resp_header_str, resp_body_str\n"
                                + "        matchString:                   # String, will be used to identify what should be replaced\n"
                                + "        matchRegex:                    # Boolean, if set then the matchString will be treated as a regex, default false\n"
                                + "        replacementString:             # String, the new string that will replace the specified selection\n"
                                + "        tokenProcessing:               # Boolean, when enabled the replacementString may contain a single token \n"
                                + "        initiators:                    # A list of integers representing the initiators (see the help)\n"));
    }

    @Test
    void shouldCopyRuleData() {
        // Given
        RuleData data =
                new RuleData(
                        "desc",
                        "url",
                        "REQ_Header",
                        "match",
                        true,
                        "repl",
                        true,
                        new Integer[] {5, 7});

        // When
        RuleData dataCopy = new RuleData(data);

        // Then
        assertThat(dataCopy.getDescription(), is("desc"));
        assertThat(dataCopy.getUrl(), is("url"));
        assertThat(dataCopy.getMatchType(), is("REQ_Header"));
        assertThat(dataCopy.getMatchString(), is("match"));
        assertThat(dataCopy.isMatchRegex(), is(true));
        assertThat(dataCopy.getTokenProcessing(), is(true));
        assertThat(data.getReplacementString(), is("repl"));
        assertThat(dataCopy.getInitiators(), is(notNullValue()));
        assertThat(dataCopy.getInitiators().length, is(2));
        assertThat(dataCopy.getInitiators()[0], is(5));
        assertThat(dataCopy.getInitiators()[1], is(7));
    }

    private static ReplacerJob createReplacerJob(String data) {
        ReplacerJob job = new ReplacerJob();
        job.setJobData(new Yaml().load(data));
        return job;
    }
}
