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
package org.zaproxy.addon.automation.jobs;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.parosproxy.paros.Constant;
import org.yaml.snakeyaml.Yaml;
import org.zaproxy.addon.automation.AutomationEnvironment;
import org.zaproxy.addon.automation.AutomationProgress;
import org.zaproxy.zap.utils.I18N;

class DelayJobUnitTest {

    @BeforeAll
    static void setUp() {
        Constant.messages = new I18N(Locale.ENGLISH);
    }

    @Test
    void shouldNotFailIfNoConfigs() {
        // Given
        DelayJob job = new DelayJob();
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);

        // When
        job.applyParameters(progress);
        job.runJob(env, progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"-", "1.1", " ", "test", "1:2:3:4"})
    void shouldFailOnInvalidYamlTimeProperty(String hHmMsS) {
        // Given
        DelayJob job = new DelayJob();
        AutomationProgress progress = new AutomationProgress();
        String yamlStr = String.join("\n", "parameters:", "  time: \"" + hHmMsS + "\"");
        Yaml yaml = new Yaml();
        Object data = yaml.load(yamlStr);
        job.setJobData((LinkedHashMap<?, ?>) data);

        // When
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
        assertThat(progress.getErrors().size(), is(1));
        assertThat(progress.getErrors().get(0), is("!automation.error.delay.badtime!"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"-", "1.1", " ", "test", "1:2:3:4"})
    void shouldFailOnInvalidTimes(String hHmMsS) {
        // Given
        DelayJob job = new DelayJob();
        AutomationProgress progress = new AutomationProgress();

        // When
        job.getParameters().setTime(hHmMsS);
        job.verifyParameters(progress);

        // Then
        assertThat(progress.hasErrors(), is(equalTo(true)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "0:", ":0", ":0:0", "0::", "::0"})
    void shouldNotSleepIfZeroSeconds(String hHmMsS) {
        // Given
        DelayJob job = new DelayJob();
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);

        // When
        job.getParameters().setTime(hHmMsS);
        job.applyParameters(progress);
        long startTime = System.currentTimeMillis();
        job.runJob(env, progress);
        long endTime = System.currentTimeMillis();

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(TimeUnit.MILLISECONDS.toSeconds(endTime - startTime), is(equalTo(0L)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"1", ":1", ":0:1", "::1"})
    void shouldSleepForGivenSeconds(String hHmMsS) {
        // Given
        DelayJob job = new DelayJob();
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);

        // When
        job.getParameters().setTime(hHmMsS);
        job.applyParameters(progress);
        long startTime = System.currentTimeMillis();
        job.runJob(env, progress);
        long endTime = System.currentTimeMillis();

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(TimeUnit.MILLISECONDS.toSeconds(endTime - startTime), is(equalTo(1L)));
    }

    @Test
    void shouldInterruptWhenMethodCalled() {
        // Given
        DelayJob job = new DelayJob();
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);
        long sleepSeconds = 2;

        // When
        job.getParameters().setTime("1:0");
        job.applyParameters(progress);

        new Thread(
                        () -> {
                            try {
                                TimeUnit.SECONDS.sleep(sleepSeconds);
                            } catch (InterruptedException e) {
                            }
                            DelayJob.setEndJob(true);
                        })
                .start();

        long startTime = System.currentTimeMillis();
        job.runJob(env, progress);
        long endTime = System.currentTimeMillis();

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertTrue(TimeUnit.MILLISECONDS.toSeconds(endTime - startTime) < 4);
    }

    @Test
    void shouldNotSleepIfFileExists() throws IOException {
        // Given
        DelayJob job = new DelayJob();
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);

        // When
        Path path = Files.createTempFile("delay-test1", ".txt");
        File file = path.toFile();
        job.getParameters().setTime("1:0");
        job.getParameters().setFileName(file.getAbsolutePath());
        job.applyParameters(progress);

        long startTime = System.currentTimeMillis();
        job.runJob(env, progress);
        long endTime = System.currentTimeMillis();

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertThat(TimeUnit.MILLISECONDS.toSeconds(endTime - startTime), is(equalTo(0L)));
    }

    @Test
    void shouldInterruptWhenFileCreated() throws IOException {
        // Given
        DelayJob job = new DelayJob();
        AutomationProgress progress = new AutomationProgress();
        AutomationEnvironment env = new AutomationEnvironment(progress);

        // When
        Path path = Files.createTempFile("delay-test2", ".txt");
        File file1 = path.toFile();
        File file2 = new File(file1.getAbsoluteFile() + "2");
        file1.renameTo(file2);

        job.getParameters().setTime("1:0");
        job.getParameters().setFileName(file1.getAbsolutePath());
        job.applyParameters(progress);

        new Thread(
                        () -> {
                            try {
                                TimeUnit.SECONDS.sleep(2);
                            } catch (InterruptedException e) {
                            }
                            file2.renameTo(file1);
                        })
                .start();

        long startTime = System.currentTimeMillis();
        job.runJob(env, progress);
        long endTime = System.currentTimeMillis();

        // Then
        assertThat(progress.hasErrors(), is(equalTo(false)));
        assertThat(progress.hasWarnings(), is(equalTo(false)));
        assertTrue(TimeUnit.MILLISECONDS.toSeconds(endTime - startTime) < 4);
    }
}
