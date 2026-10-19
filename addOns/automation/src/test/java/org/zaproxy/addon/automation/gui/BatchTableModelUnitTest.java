/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.automation.gui;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

import java.io.File;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.ExtensionAutomation;
import org.zaproxy.addon.automation.PlanBatch;
import org.zaproxy.addon.automation.PlanBatch.Status;
import org.zaproxy.zap.testutils.TestUtils;

/** Unit tests for {@link BatchTableModel}. */
class BatchTableModelUnitTest extends TestUtils {

    private static final File A = new File("a.yaml");
    private static final File B = new File("b.yaml");

    private BatchTableModel model;

    @BeforeEach
    void setUp() {
        mockMessages(new ExtensionAutomation());
        model = new BatchTableModel();
        model.setFiles(List.of(A, B));
    }

    @AfterEach
    void cleanUp() {
        Constant.messages = null;
    }

    /** Runs the plans of a batch which fails at the second one, to get entries to update with. */
    private static PlanBatch.Entry run(File file, Status status) {
        PlanBatch batch =
                new PlanBatch(
                        List.of(file),
                        f -> {
                            if (status == Status.LOAD_ERROR) {
                                throw new java.io.IOException("bad");
                            }
                            var plan =
                                    org.mockito.Mockito.mock(
                                            org.zaproxy.addon.automation.AutomationPlan.class);
                            return plan;
                        },
                        p -> {
                            var progress = new org.zaproxy.addon.automation.AutomationProgress();
                            progress.setQuietMode(true);
                            if (status == Status.FAIL) {
                                progress.error("failed");
                            }
                            return progress;
                        });
        batch.run();
        return batch.getEntries().get(0);
    }

    @Test
    void shouldListTheFilesAsNotRun() {
        assertThat(model.getRowCount(), is(equalTo(2)));
        assertThat(model.getValueAt(0, 0), is(equalTo("a.yaml")));
        assertThat(model.getValueAt(0, 1), is(equalTo("Not Run")));
        assertThat(model.getFiles(), contains(A, B));
        assertThat(model.getFirstProblemRow(), is(equalTo(-1)));
    }

    @Test
    void shouldUpdateTheRowOfThePlan() {
        // When
        model.update(run(B, Status.PASS));
        // Then
        assertThat(model.getStatus(0), is(equalTo(Status.NOT_RUN)));
        assertThat(model.getStatus(1), is(equalTo(Status.PASS)));
        assertThat(model.getValueAt(1, 1), is(equalTo("Pass")));
    }

    @Test
    void shouldFindFirstRowWithProblemAndItsErrors() {
        // When
        model.update(run(A, Status.PASS));
        model.update(run(B, Status.FAIL));
        // Then
        assertThat(model.getFirstProblemRow(), is(equalTo(1)));
        assertThat(model.getErrors(1), contains("failed"));
        assertThat(model.getErrors(0), is(empty()));
    }

    @Test
    void shouldTreatLoadErrorAsProblem() {
        // When
        model.update(run(A, Status.LOAD_ERROR));
        // Then
        assertThat(model.getFirstProblemRow(), is(equalTo(0)));
        assertThat(model.getValueAt(0, 1), is(equalTo("Load Error")));
    }

    @Test
    void shouldResetOnlyTheFilesGiven() {
        // Given
        model.update(run(A, Status.FAIL));
        model.update(run(B, Status.PASS));
        // When
        model.reset(List.of(A));
        // Then
        assertThat(model.getStatus(0), is(equalTo(Status.NOT_RUN)));
        assertThat(model.getErrors(0), is(empty()));
        assertThat(model.getStatus(1), is(equalTo(Status.PASS)));
    }

    @Test
    void shouldIgnoreUpdateForUnlistedPlan() {
        // When
        model.update(run(new File("other.yaml"), Status.FAIL));
        // Then
        assertThat(model.getFirstProblemRow(), is(equalTo(-1)));
    }
}
