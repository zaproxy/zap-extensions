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

import java.io.File;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.function.Consumer;

/**
 * Runs a batch of plans, one after the other, stopping at the first one that fails.
 *
 * <p>A plan fails if it cannot be loaded or if it finishes with errors, which is the same as the
 * plans run with the command line option {@code -autorun}. Warnings do not make a plan fail.
 *
 * <p>The files are not validated when listed, they are only read when they are run.
 */
public class PlanBatch {

    /** The status of a plan in the batch. */
    public enum Status {
        NOT_RUN,
        RUNNING,
        PASS,
        FAIL,
        /** The file could not be loaded as a plan. */
        LOAD_ERROR,
        /** The batch was stopped while the plan was running. */
        STOPPED
    }

    /** The state of one plan in the batch. */
    public static class Entry {

        private final File file;
        private volatile Status status = Status.NOT_RUN;
        private volatile List<String> errors = List.of();

        private Entry(File file) {
            this.file = file;
        }

        public File getFile() {
            return file;
        }

        public Status getStatus() {
            return status;
        }

        /** The errors of the plan, empty if there were none. */
        public List<String> getErrors() {
            return errors;
        }

        private void set(Status status, List<String> errors) {
            this.errors = List.copyOf(errors);
            this.status = status;
        }
    }

    /** Loads a plan from a file. */
    @FunctionalInterface
    public interface PlanLoader {
        AutomationPlan load(File file) throws IOException;
    }

    /** Runs a plan, returning when it has finished. */
    @FunctionalInterface
    public interface PlanRunner {
        AutomationProgress run(AutomationPlan plan);
    }

    private final PlanLoader loader;
    private final PlanRunner runner;
    private final List<Entry> entries;
    private Consumer<Entry> listener = e -> {};
    private volatile boolean stopped;
    private volatile AutomationPlan currentPlan;

    /**
     * Constructs a batch for the given files, in the given order.
     *
     * @param files the plans to run.
     * @param loader loads the plans.
     * @param runner runs the plans.
     */
    public PlanBatch(List<File> files, PlanLoader loader, PlanRunner runner) {
        this.loader = loader;
        this.runner = runner;
        List<Entry> list = new ArrayList<>();
        files.forEach(f -> list.add(new Entry(f)));
        this.entries = Collections.unmodifiableList(list);
    }

    /**
     * Lists the plans in a directory, the files with the extension {@code .yaml}, sorted by name.
     * Sub-directories are not included.
     *
     * @param dir the directory.
     * @return the files, empty if the directory could not be read.
     */
    public static List<File> listPlans(File dir) {
        List<File> files = new ArrayList<>();
        if (dir == null || !dir.isDirectory()) {
            return files;
        }
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir.toPath(), "*.yaml")) {
            for (Path path : stream) {
                if (Files.isRegularFile(path)) {
                    files.add(path.toFile());
                }
            }
        } catch (IOException e) {
            return new ArrayList<>();
        }
        files.sort(Comparator.comparing(File::getName));
        return files;
    }

    public List<Entry> getEntries() {
        return entries;
    }

    /**
     * Sets the listener notified, on the thread running the batch, each time the state of a plan
     * changes.
     */
    public void setListener(Consumer<Entry> listener) {
        this.listener = listener == null ? e -> {} : listener;
    }

    /**
     * Runs the plans in order, until one fails or the batch is stopped. The plans not run have the
     * status {@link Status#NOT_RUN}.
     *
     * @return {@code true} if all of the plans passed.
     * @see #run(boolean)
     */
    public boolean run() {
        return run(true);
    }

    /**
     * Runs the plans in order, until the batch is stopped or, if requested, one fails. The plans
     * not run have the status {@link Status#NOT_RUN}.
     *
     * @param stopOnFailure {@code true} to stop at the first plan that fails, {@code false} to run
     *     all of the plans.
     * @return {@code true} if all of the plans passed.
     */
    public boolean run(boolean stopOnFailure) {
        stopped = false;
        boolean passed = true;
        entries.forEach(e -> e.set(Status.NOT_RUN, List.of()));
        for (Entry entry : entries) {
            if (stopped) {
                return false;
            }
            if (!run(entry)) {
                if (stopOnFailure) {
                    return false;
                }
                passed = false;
            }
        }
        return passed && !stopped;
    }

    /** Stops the batch, including the plan currently running, if any. */
    public void stop() {
        stopped = true;
        AutomationPlan plan = currentPlan;
        if (plan != null) {
            plan.stopPlan();
        }
    }

    private boolean run(Entry entry) {
        update(entry, Status.RUNNING, List.of());
        AutomationPlan plan;
        try {
            plan = loader.load(entry.getFile());
        } catch (Exception e) {
            update(entry, Status.LOAD_ERROR, List.of(String.valueOf(e.getMessage())));
            return false;
        }

        AutomationProgress progress;
        currentPlan = plan;
        try {
            progress = runner.run(plan);
        } catch (Exception e) {
            update(entry, Status.FAIL, List.of(String.valueOf(e.getMessage())));
            return false;
        } finally {
            currentPlan = null;
        }

        if (stopped) {
            update(entry, Status.STOPPED, progress.getErrors());
            return false;
        }
        if (progress.hasErrors()) {
            update(entry, Status.FAIL, progress.getErrors());
            return false;
        }
        update(entry, Status.PASS, List.of());
        return true;
    }

    private void update(Entry entry, Status status, List<String> errors) {
        entry.set(status, errors);
        listener.accept(entry);
    }

    /** Gets a summary of the plans, one line for each, in the style of the integration tests. */
    public String getSummary() {
        StringBuilder sb = new StringBuilder();
        for (Entry entry : entries) {
            sb.append("Plan: ")
                    .append(entry.getFile().getName())
                    .append('\t')
                    .append(entry.getStatus())
                    .append('\n');
        }
        return sb.toString();
    }
}
