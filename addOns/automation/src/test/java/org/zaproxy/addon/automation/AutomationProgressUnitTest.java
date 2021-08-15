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
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.automation.AutomationProgress.JobResults;
import org.zaproxy.zap.testutils.TestUtils;

class AutomationProgressUnitTest extends TestUtils {

    private AutomationProgress progress;

    @BeforeEach
    void setUp() {
        progress = new AutomationProgress();
    }

    @Test
    void shouldLogErrors() {
        // Given
        String error1 = "error1";
        String error2 = "error2";

        // When
        progress.error(error1);
        progress.error(error2);

        // Then
        assertThat(progress.hasErrors(), is(true));
        assertThat(progress.hasWarnings(), is(false));
        assertThat(progress.getErrors().size(), is(2));
        assertThat(progress.getErrors().get(0), is(error1));
        assertThat(progress.getErrors().get(1), is(error2));
    }

    @Test
    void shouldLogWarnings() {
        // Given
        String warn1 = "warn1";
        String warn2 = "warn2";
        String warn3 = "warn3";

        // When
        progress.warn(warn1);
        progress.warn(warn2);
        progress.warn(warn3);

        // Then
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.hasWarnings(), is(true));
        assertThat(progress.getWarnings().size(), is(3));
        assertThat(progress.getWarnings().get(0), is(warn1));
        assertThat(progress.getWarnings().get(1), is(warn2));
        assertThat(progress.getWarnings().get(2), is(warn3));
    }

    @Test
    void shouldLogInfos() {
        // Given
        String info1 = "info1";
        String info2 = "info2";

        // When
        progress.info(info1);
        progress.info(info2);

        // Then
        assertThat(progress.hasErrors(), is(false));
        assertThat(progress.hasWarnings(), is(false));
        assertThat(progress.getInfos().size(), is(2));
        assertThat(progress.getInfos().get(0), is(info1));
        assertThat(progress.getInfos().get(1), is(info2));
    }

    @Test
    void shouldReturnJobErrors() {
        // Given
        AutomationJob job1 = mock(AutomationJob.class);
        AutomationJob job2 = mock(AutomationJob.class);
        AutomationJob job3 = mock(AutomationJob.class);
        String job1error1 = "job1error1";
        String job1error2 = "job1error2";
        String job3error1 = "job3error1";

        // When
        progress.error(job1error1);
        progress.error(job1error2);
        progress.addRunJob(job1);
        progress.addRunJob(job2);
        progress.error(job3error1);
        progress.addRunJob(job3);
        JobResults job1res = progress.getJobResults(job1);
        JobResults job2res = progress.getJobResults(job2);
        JobResults job3res = progress.getJobResults(job3);

        // Then
        assertThat(job1res.getErrors().size(), is(2));
        assertThat(job1res.getErrors().get(0), is(job1error1));
        assertThat(job1res.getErrors().get(1), is(job1error2));
        assertThat(job2res.getErrors().size(), is(0));
        assertThat(job3res.getErrors().size(), is(1));
        assertThat(job3res.getErrors().get(0), is(job3error1));

        assertThat(progress.getErrors(job1).size(), is(2));
        assertThat(progress.getErrors(job1).get(0), is(job1error1));
        assertThat(progress.getErrors(job1).get(1), is(job1error2));
        assertThat(progress.getErrors(job2).size(), is(0));
        assertThat(progress.getErrors(job3).size(), is(1));
        assertThat(progress.getErrors(job3).get(0), is(job3error1));
    }

    @Test
    void shouldReturnJobWarnings() {
        // Given
        AutomationJob job1 = mock(AutomationJob.class);
        AutomationJob job2 = mock(AutomationJob.class);
        AutomationJob job3 = mock(AutomationJob.class);
        String job2warn1 = "job2warn1";
        String job2warn2 = "job2warn2";
        String job3warn1 = "job3warn1";
        String job3warn2 = "job3warn2";
        String job3warn3 = "job3warn3";

        // When
        progress.addRunJob(job1);
        progress.warn(job2warn1);
        progress.warn(job2warn2);
        progress.addRunJob(job2);
        progress.warn(job3warn1);
        progress.warn(job3warn2);
        progress.warn(job3warn3);
        progress.addRunJob(job3);
        JobResults job1res = progress.getJobResults(job1);
        JobResults job2res = progress.getJobResults(job2);
        JobResults job3res = progress.getJobResults(job3);

        // Then
        assertThat(job1res.getWarnings().size(), is(0));
        assertThat(job2res.getWarnings().size(), is(2));
        assertThat(job2res.getWarnings().get(0), is(job2warn1));
        assertThat(job2res.getWarnings().get(1), is(job2warn2));
        assertThat(job3res.getWarnings().size(), is(3));
        assertThat(job3res.getWarnings().get(0), is(job3warn1));
        assertThat(job3res.getWarnings().get(1), is(job3warn2));
        assertThat(job3res.getWarnings().get(2), is(job3warn3));

        assertThat(progress.getWarnings(job1).size(), is(0));
        assertThat(progress.getWarnings(job2).size(), is(2));
        assertThat(progress.getWarnings(job2).get(0), is(job2warn1));
        assertThat(progress.getWarnings(job2).get(1), is(job2warn2));
        assertThat(progress.getWarnings(job3).size(), is(3));
        assertThat(progress.getWarnings(job3).get(0), is(job3warn1));
        assertThat(progress.getWarnings(job3).get(1), is(job3warn2));
        assertThat(progress.getWarnings(job3).get(2), is(job3warn3));
    }

    @Test
    void shouldReturnJobInfos() {
        // Given
        AutomationJob job1 = mock(AutomationJob.class);
        AutomationJob job2 = mock(AutomationJob.class);
        AutomationJob job3 = mock(AutomationJob.class);
        String job1info1 = "job2info1";
        String job2info1 = "job3info1";
        String job2info2 = "job3info2";

        // When
        progress.info(job1info1);
        progress.addRunJob(job1);
        progress.info(job2info1);
        progress.info(job2info2);
        progress.addRunJob(job2);
        progress.addRunJob(job3);
        JobResults job1res = progress.getJobResults(job1);
        JobResults job2res = progress.getJobResults(job2);
        JobResults job3res = progress.getJobResults(job3);

        // Then
        assertThat(job1res.getInfos().size(), is(1));
        assertThat(job1res.getInfos().get(0), is(job1info1));
        assertThat(job2res.getInfos().size(), is(2));
        assertThat(job2res.getInfos().get(0), is(job2info1));
        assertThat(job2res.getInfos().get(1), is(job2info2));
        assertThat(job3res.getInfos().size(), is(0));

        assertThat(progress.getInfos(job1).size(), is(1));
        assertThat(progress.getInfos(job1).get(0), is(job1info1));
        assertThat(progress.getInfos(job2).size(), is(2));
        assertThat(progress.getInfos(job2).get(0), is(job2info1));
        assertThat(progress.getInfos(job2).get(1), is(job2info2));
        assertThat(progress.getInfos(job3).size(), is(0));
    }

    @Test
    void shouldReturnEmptyResultsForUnrunJobs() {
        // Given
        AutomationJob job1 = mock(AutomationJob.class);

        // When
        progress.info("info");
        progress.warn("warn");
        progress.error("error");
        JobResults job1res = progress.getJobResults(job1);

        // Then
        assertThat(job1res.getErrors().size(), is(0));
        assertThat(job1res.getWarnings().size(), is(0));
        assertThat(job1res.getInfos().size(), is(0));

        assertThat(progress.getErrors(job1).size(), is(0));
        assertThat(progress.getWarnings(job1).size(), is(0));
        assertThat(progress.getInfos(job1).size(), is(0));
    }
}
