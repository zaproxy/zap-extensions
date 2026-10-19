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
package org.zaproxy.addon.automation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.zaproxy.addon.automation.PlanBatch.Entry;
import org.zaproxy.addon.automation.PlanBatch.Status;

/** Unit tests for {@link PlanBatch}. */
class PlanBatchUnitTest {

    @TempDir Path dir;

    private final Map<File, AutomationPlan> plans = new HashMap<>();
    private final Map<AutomationPlan, AutomationProgress> results = new HashMap<>();
    private final List<String> ran = new ArrayList<>();

    private File file(String name) {
        return dir.resolve(name).toFile();
    }

    /** Adds a plan which finishes with the given errors and warnings. */
    private File plan(String name, int errors, int warnings) {
        File file = file(name);
        AutomationPlan plan = mock(AutomationPlan.class);
        AutomationProgress progress = new AutomationProgress();
        progress.setQuietMode(true);
        for (int i = 0; i < errors; i++) {
            progress.error("error " + i + " in " + name);
        }
        for (int i = 0; i < warnings; i++) {
            progress.warn("warning " + i + " in " + name);
        }
        plans.put(file, plan);
        results.put(plan, progress);
        return file;
    }

    private PlanBatch batch(File... files) {
        return new PlanBatch(
                List.of(files),
                f -> {
                    AutomationPlan plan = plans.get(f);
                    if (plan == null) {
                        throw new IOException("Cannot load " + f.getName());
                    }
                    return plan;
                },
                plan -> {
                    ran.add(String.valueOf(results.get(plan).getAllMessages().size()));
                    return results.get(plan);
                });
    }

    private static List<Status> statuses(PlanBatch batch) {
        return batch.getEntries().stream().map(Entry::getStatus).toList();
    }

    @Test
    void shouldListYamlFilesSortedByName() throws IOException {
        // Given
        for (String name : List.of("b.yaml", "a.yaml", "c.yaml.disabled", "d.txt", "e.yml")) {
            Files.writeString(dir.resolve(name), "x");
        }
        Files.createDirectory(dir.resolve("sub.yaml"));
        // When
        List<File> files = PlanBatch.listPlans(dir.toFile());
        // Then
        assertThat(files.stream().map(File::getName).toList(), contains("a.yaml", "b.yaml"));
    }

    @Test
    void shouldNotValidateTheFilesListed() throws IOException {
        // Given
        Files.writeString(dir.resolve("bad.yaml"), "this: [is not: a plan");
        // When
        List<File> files = PlanBatch.listPlans(dir.toFile());
        // Then
        assertThat(files.size(), is(equalTo(1)));
    }

    @Test
    void shouldListNothingForMissingDirectoryOrNull() {
        assertThat(PlanBatch.listPlans(file("missing")), is(empty()));
        assertThat(PlanBatch.listPlans(null), is(empty()));
    }

    @Test
    void shouldPassIfAllPlansPass() {
        // Given
        PlanBatch batch = batch(plan("a.yaml", 0, 0), plan("b.yaml", 0, 0));
        // When
        boolean result = batch.run();
        // Then
        assertThat(result, is(equalTo(true)));
        assertThat(statuses(batch), contains(Status.PASS, Status.PASS));
        assertThat(ran.size(), is(equalTo(2)));
    }

    @Test
    void shouldNotFailForWarnings() {
        // Given
        PlanBatch batch = batch(plan("a.yaml", 0, 2));
        // When
        boolean result = batch.run();
        // Then
        assertThat(result, is(equalTo(true)));
        assertThat(statuses(batch), contains(Status.PASS));
    }

    @Test
    void shouldStopAtFirstFailure() {
        // Given
        PlanBatch batch = batch(plan("a.yaml", 0, 0), plan("b.yaml", 2, 0), plan("c.yaml", 0, 0));
        // When
        boolean result = batch.run();
        // Then
        assertThat(result, is(equalTo(false)));
        assertThat(statuses(batch), contains(Status.PASS, Status.FAIL, Status.NOT_RUN));
        assertThat(batch.getEntries().get(1).getErrors().size(), is(equalTo(2)));
        assertThat(ran.size(), is(equalTo(2)));
    }

    @Test
    void shouldRunAllPlansButFailIfAnyFailsWhenNotStoppingOnFailure() {
        // Given
        PlanBatch batch = batch(plan("a.yaml", 0, 0), plan("b.yaml", 2, 0), plan("c.yaml", 0, 0));
        // When
        boolean result = batch.run(false);
        // Then
        assertThat(result, is(equalTo(false)));
        assertThat(statuses(batch), contains(Status.PASS, Status.FAIL, Status.PASS));
        assertThat(ran.size(), is(equalTo(3)));
    }

    @Test
    void shouldRunPlansAfterOneThatCannotBeLoadedWhenNotStoppingOnFailure() {
        // Given
        PlanBatch batch = batch(file("missing.yaml"), plan("b.yaml", 0, 0));
        // When
        boolean result = batch.run(false);
        // Then
        assertThat(result, is(equalTo(false)));
        assertThat(statuses(batch), contains(Status.LOAD_ERROR, Status.PASS));
    }

    @Test
    void shouldPassWhenNotStoppingOnFailureAndAllPass() {
        // Given
        PlanBatch batch = batch(plan("a.yaml", 0, 1), plan("b.yaml", 0, 0));
        // When
        boolean result = batch.run(false);
        // Then
        assertThat(result, is(equalTo(true)));
    }

    @Test
    void shouldStopAtPlanThatCannotBeLoaded() {
        // Given
        PlanBatch batch = batch(plan("a.yaml", 0, 0), file("missing.yaml"), plan("c.yaml", 0, 0));
        // When
        boolean result = batch.run();
        // Then
        assertThat(result, is(equalTo(false)));
        assertThat(statuses(batch), contains(Status.PASS, Status.LOAD_ERROR, Status.NOT_RUN));
        assertThat(batch.getEntries().get(1).getErrors(), contains("Cannot load missing.yaml"));
    }

    @Test
    void shouldFailIfPlanRunnerThrows() {
        // Given
        File file = file("a.yaml");
        AutomationPlan plan = mock(AutomationPlan.class);
        PlanBatch batch =
                new PlanBatch(
                        List.of(file),
                        f -> plan,
                        p -> {
                            throw new IllegalStateException("boom");
                        });
        // When
        boolean result = batch.run();
        // Then
        assertThat(result, is(equalTo(false)));
        assertThat(statuses(batch), contains(Status.FAIL));
        assertThat(batch.getEntries().get(0).getErrors(), contains("boom"));
    }

    @Test
    void shouldStopRunningPlanAndBatchWhenStopped() {
        // Given
        File first = file("a.yaml");
        File second = file("b.yaml");
        AutomationPlan plan = mock(AutomationPlan.class);
        PlanBatch[] holder = new PlanBatch[1];
        holder[0] =
                new PlanBatch(
                        List.of(first, second),
                        f -> plan,
                        p -> {
                            holder[0].stop();
                            return new AutomationProgress();
                        });
        // When
        boolean result = holder[0].run();
        // Then
        assertThat(result, is(equalTo(false)));
        assertThat(statuses(holder[0]), contains(Status.STOPPED, Status.NOT_RUN));
        verify(plan).stopPlan();
    }

    @Test
    void shouldNotifyListenerOfEachChange() {
        // Given
        PlanBatch batch = batch(plan("a.yaml", 0, 0), plan("b.yaml", 1, 0));
        List<String> events = new ArrayList<>();
        batch.setListener(e -> events.add(e.getFile().getName() + " " + e.getStatus()));
        // When
        batch.run();
        // Then
        assertThat(
                events, contains("a.yaml RUNNING", "a.yaml PASS", "b.yaml RUNNING", "b.yaml FAIL"));
    }

    @Test
    void shouldResetPreviousResultsWhenRunAgain() {
        // Given
        PlanBatch batch = batch(plan("a.yaml", 1, 0), plan("b.yaml", 0, 0));
        batch.run();
        // When
        results.put(plans.get(file("a.yaml")), new AutomationProgress());
        boolean result = batch.run();
        // Then
        assertThat(result, is(equalTo(true)));
        assertThat(statuses(batch), contains(Status.PASS, Status.PASS));
        assertThat(batch.getEntries().get(0).getErrors(), is(empty()));
    }

    @Test
    void shouldSummariseThePlans() {
        // Given
        PlanBatch batch = batch(plan("a.yaml", 0, 0), plan("b.yaml", 1, 0), plan("c.yaml", 0, 0));
        batch.run();
        // When
        String summary = batch.getSummary();
        // Then
        assertThat(
                summary,
                is(equalTo("Plan: a.yaml\tPASS\nPlan: b.yaml\tFAIL\nPlan: c.yaml\tNOT_RUN\n")));
    }
}
