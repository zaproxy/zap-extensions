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
package org.zaproxy.addon.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.CommandLineArgument;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.model.Model;
import org.zaproxy.addon.automation.jobs.ActiveScanJob;
import org.zaproxy.addon.automation.jobs.AddOnJob;
import org.zaproxy.addon.automation.jobs.PassiveScanConfigJob;
import org.zaproxy.addon.automation.jobs.PassiveScanWaitJob;
import org.zaproxy.addon.automation.jobs.SpiderJob;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.testutils.TestUtils;
import org.zaproxy.zap.utils.I18N;
import org.zaproxy.zap.utils.ZapXmlConfiguration;

class ExtentionAutomationUnitTest extends TestUtils {

    private static MockedStatic<CommandLine> mockedCmdLine;

    @BeforeAll
    static void init() {
        mockedCmdLine = Mockito.mockStatic(CommandLine.class);
    }

    @AfterAll
    static void close() {
        mockedCmdLine.close();
    }

    @BeforeEach
    void setUp() throws Exception {
        Constant.messages = new I18N(Locale.ENGLISH);
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
    }

    @Test
    void shouldReturnDefaultData() {
        // Given / When
        ExtensionAutomation extAuto = new ExtensionAutomation();

        // Then
        assertThat(extAuto.canUnload(), is(equalTo(true)));
        assertThat(extAuto.getI18nPrefix(), is(equalTo("automation")));
        assertThat(extAuto.getAuthor(), is(equalTo("ZAP Dev Team")));
    }

    @Test
    void shouldRegisterBuiltInJobs() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();

        // When
        Map<String, AutomationJob> jobs = extAuto.getAutomationJobs();

        // Then
        assertThat(jobs.size(), is(equalTo(5)));
        assertThat(jobs.containsKey(AddOnJob.JOB_NAME), is(equalTo(true)));
        assertThat(jobs.containsKey(PassiveScanConfigJob.JOB_NAME), is(equalTo(true)));
        assertThat(jobs.containsKey(PassiveScanWaitJob.JOB_NAME), is(equalTo(true)));
        assertThat(jobs.containsKey(SpiderJob.JOB_NAME), is(equalTo(true)));
        assertThat(jobs.containsKey(ActiveScanJob.JOB_NAME), is(equalTo(true)));
    }

    @Test
    void shouldRegisterNewJob() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        String jobName = "testjob";

        AutomationJob job =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return jobName;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };

        // When
        extAuto.registerAutomationJob(job);
        Map<String, AutomationJob> jobs = extAuto.getAutomationJobs();

        // Then
        assertThat(jobs.size(), is(equalTo(6)));
        assertThat(jobs.containsKey(jobName), is(equalTo(true)));
    }

    @Test
    void shouldUnregisterExistingJob() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();

        // When
        Map<String, AutomationJob> jobs = extAuto.getAutomationJobs();
        int origSize = jobs.size();
        extAuto.unregisterAutomationJob(jobs.get(SpiderJob.JOB_NAME));

        // Then
        assertThat(jobs.size(), is(equalTo(origSize - 1)));
        assertThat(jobs.containsKey(SpiderJob.JOB_NAME), is(equalTo(false)));
    }

    @Test
    void shouldCreateMinTemplateFile() throws Exception {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        Path filePath = getResourcePath("resources/template-min.yaml");
        String expectedTemplate = new String(Files.readAllBytes(filePath));

        // When
        File f = File.createTempFile("ZAP-min-template-test", ".yaml");
        extAuto.generateTemplateFile(f.getAbsolutePath(), false);
        String generatedTemplate = new String(Files.readAllBytes(f.toPath()));

        // Then
        // If this fails then the easiest option is to generate the file using the cmdline option,
        // manually check it and then replace it in the resources directory
        assertThat(generatedTemplate.length(), is(equalTo(expectedTemplate.length())));
        assertThat(generatedTemplate, is(equalTo(expectedTemplate)));
    }

    @Test
    void shouldCreateMaxTemplateFile() throws Exception {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        Path filePath = getResourcePath("resources/template-max.yaml");
        String expectedTemplate = new String(Files.readAllBytes(filePath));

        // When
        File f = File.createTempFile("ZAP-max-template-test", ".yaml");
        extAuto.generateTemplateFile(f.getAbsolutePath(), true);
        String generatedTemplate = new String(Files.readAllBytes(f.toPath()));

        // Then
        // If this fails then the easiest option is to generate the file using the cmdline option,
        // manually check it and then replace it in the resources directory
        assertThat(generatedTemplate.length(), is(equalTo(expectedTemplate.length())));
        assertThat(generatedTemplate, is(equalTo(expectedTemplate)));
    }

    @Test
    void shouldCreateConfigTemplateFile() throws Exception {
        // Given
        Model model = mock(Model.class, withSettings().defaultAnswer(CALLS_REAL_METHODS));
        Model.setSingletonForTesting(model);
        ExtensionLoader extensionLoader = mock(ExtensionLoader.class, withSettings().lenient());

        ExtensionPassiveScan extPscan = mock(ExtensionPassiveScan.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionPassiveScan.class)).willReturn(extPscan);

        ExtensionSpider extSpider = mock(ExtensionSpider.class, withSettings().lenient());
        given(extensionLoader.getExtension(ExtensionSpider.class)).willReturn(extSpider);

        Control.initSingletonForTesting(Model.getSingleton(), extensionLoader);
        Model.getSingleton().getOptionsParam().load(new ZapXmlConfiguration());

        ExtensionAutomation extAuto = new ExtensionAutomation();
        Path filePath = getResourcePath("resources/template-config.yaml");
        String expectedTemplate = new String(Files.readAllBytes(filePath));

        // When
        File f = File.createTempFile("ZAP-config-template-test", ".yaml");
        extAuto.generateConfigFile(f.getAbsolutePath());
        String generatedTemplate = new String(Files.readAllBytes(f.toPath()));

        // Then
        assertThat(generatedTemplate.length(), is(equalTo(expectedTemplate.length())));
        assertThat(generatedTemplate, is(equalTo(expectedTemplate)));
    }

    @Test
    void shouldRunPlan() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        String job1Name = "job1";
        String job2Name = "job2";
        String job3Name = "job3";

        AutomationJobImpl job1 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job1Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        AutomationJobImpl job2 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job2Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        AutomationJobImpl job3 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job3Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        Path filePath = getResourcePath("resources/testplan-failonerror.yaml");

        // When
        extAuto.registerAutomationJob(job1);
        extAuto.registerAutomationJob(job2);
        extAuto.registerAutomationJob(job3);
        AutomationProgress progress =
                extAuto.runAutomationFile(filePath.toAbsolutePath().toString());

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(job1.wasRun(), is(equalTo(true)));
        assertThat(job2.wasRun(), is(equalTo(true)));
        assertThat(job3.wasRun(), is(equalTo(true)));
    }

    @Test
    void shouldFailPlanOnError() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        String job1Name = "job1";
        String job3Name = "job3";

        AutomationJobImpl job1 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job1Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        AutomationJobImpl job3 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job3Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        Path filePath = getResourcePath("resources/testplan-failonerror.yaml");

        // When
        extAuto.registerAutomationJob(job1);
        extAuto.registerAutomationJob(job3);
        AutomationProgress progress =
                extAuto.runAutomationFile(filePath.toAbsolutePath().toString());

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(job1.wasRun(), is(equalTo(true)));
        assertThat(job3.wasRun(), is(equalTo(false)));
    }

    @Test
    void shouldReturnCmdLineArgs() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();

        // When
        CommandLineArgument[] args = extAuto.getCommandLineArguments();

        // Then
        assertThat(args.length, is(equalTo(4)));
        assertThat(args[0].getName(), is(equalTo("-autorun")));
        assertThat(args[0].getNumOfArguments(), is(equalTo(1)));
        assertThat(args[1].getName(), is(equalTo("-autogenmin")));
        assertThat(args[1].getNumOfArguments(), is(equalTo(1)));
        assertThat(args[2].getName(), is(equalTo("-autogenmax")));
        assertThat(args[2].getNumOfArguments(), is(equalTo(1)));
        assertThat(args[3].getName(), is(equalTo("-autogenconf")));
        assertThat(args[3].getNumOfArguments(), is(equalTo(1)));
    }

    @Test
    void shouldRunPlanWithWarnings() {
        // Given
        ExtensionAutomation extAuto = new ExtensionAutomation();
        String job1Name = "job1";
        String job2Name = "job2";
        String job3Name = "job3";

        AutomationJobImpl job1 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job1Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        AutomationJobImpl job2 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job2Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        AutomationJobImpl job3 =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return job3Name;
                    }

                    @Override
                    public Order getOrder() {
                        return Order.REPORT;
                    }
                };
        Path filePath = getResourcePath("resources/testplan-withwarnings.yaml");

        // When
        extAuto.registerAutomationJob(job1);
        extAuto.registerAutomationJob(job2);
        extAuto.registerAutomationJob(job3);
        AutomationProgress progress =
                extAuto.runAutomationFile(filePath.toAbsolutePath().toString());

        // Then
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(progress.getWarnings().get(0), is(equalTo("!automation.error.job.name!")));
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(job1.wasRun(), is(equalTo(true)));
        assertThat(job1.getName(), is(equalTo("Job 1")));
        assertThat(job2.wasRun(), is(equalTo(true)));
        assertThat(job2.getName(), is(equalTo("job2")));
        assertThat(job3.wasRun(), is(equalTo(true)));
    }

    @Test
    void shouldFailPlanOnErrorApplyingParameters() {
        // Given
        AutomationJobImpl job =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return "job";
                    }

                    @Override
                    public Order getOrder() {
                        return Order.EXPLORE;
                    }

                    @Override
                    public Object getParamMethodObject() {
                        return new TestParamContainer();
                    }

                    @Override
                    public String getParamMethodName() {
                        return "getTestParam";
                    }
                };
        ExtensionAutomation extAuto = new ExtensionAutomation();
        Path filePath = getResourcePath("resources/testPlan-failOnErrorApplyingParameters.yaml");

        // When
        extAuto.registerAutomationJob(job);
        AutomationProgress progress =
                extAuto.runAutomationFile(filePath.toAbsolutePath().toString());

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(progress.getErrors().size(), is(equalTo(1)));
        assertThat(progress.getErrors().get(0), is(equalTo("!automation.error.options.badbool!")));
        assertThat(job.wasRun(), is(equalTo(false)));
    }

    @Test
    void shouldFailPlanOnWarningApplyingParameters() {
        // Given
        AutomationJobImpl job =
                new AutomationJobImpl() {
                    @Override
                    public String getType() {
                        return "job";
                    }

                    @Override
                    public Order getOrder() {
                        return Order.EXPLORE;
                    }

                    @Override
                    public Object getParamMethodObject() {
                        return new TestParamContainer();
                    }

                    @Override
                    public String getParamMethodName() {
                        return "getTestParam";
                    }
                };
        ExtensionAutomation extAuto = new ExtensionAutomation();
        Path filePath = getResourcePath("resources/testPlan-failOnWarningApplyingParameters.yaml");

        // When
        extAuto.registerAutomationJob(job);
        AutomationProgress progress =
                extAuto.runAutomationFile(filePath.toAbsolutePath().toString());

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(true)));
        assertThat(progress.getWarnings().size(), is(equalTo(1)));
        assertThat(
                progress.getWarnings().get(0), is(equalTo("!automation.error.options.unknown!")));
        assertThat(job.wasRun(), is(equalTo(false)));
    }

    // Methods are accessed via reflection
    @SuppressWarnings("unused")
    private static class TestParamContainer {

        private TestParam testParam = new TestParam();

        public TestParam getTestParam() {
            return testParam;
        }
    }

    // Methods are accessed via reflection
    @SuppressWarnings("unused")
    private static class TestParam {

        private boolean boolParam;

        public void setBoolParam(boolean boolParam) {
            this.boolParam = boolParam;
        }
    }

    private static class AutomationJobImpl extends AutomationJob {

        private boolean wasRun = false;

        @Override
        public void runJob(
                AutomationEnvironment env,
                LinkedHashMap<?, ?> jobData,
                AutomationProgress progress) {
            wasRun = true;
        }

        public boolean wasRun() {
            return wasRun;
        }

        @Override
        public String getType() {
            return null;
        }

        @Override
        public Order getOrder() {
            return null;
        }

        @Override
        public Object getParamMethodObject() {
            return null;
        }

        @Override
        public String getParamMethodName() {
            return null;
        }
    }
}
