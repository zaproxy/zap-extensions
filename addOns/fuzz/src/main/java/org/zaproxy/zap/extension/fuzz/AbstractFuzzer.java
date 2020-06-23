/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.SortedSet;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacement;
import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacementGenerator;
import org.zaproxy.zap.extension.fuzz.messagelocations.MultipleMessageLocationsReplacer;
import org.zaproxy.zap.extension.fuzz.messagelocations.ReplacementException;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.model.InvalidMessageException;
import org.zaproxy.zap.utils.ExecutorTerminatedListener;
import org.zaproxy.zap.utils.PausableExecutorService;
import org.zaproxy.zap.utils.PausableScheduledThreadPoolExecutor;
import org.zaproxy.zap.utils.PausableThreadPoolExecutor;

/**
 * An abstract {@code Fuzzer} that allows to fuzz a message.
 *
 * @param <M> the type of message fuzzed by this fuzzer
 */
public abstract class AbstractFuzzer<M extends Message> implements Fuzzer<M> {

    private static enum State {
        NOT_STARTED,
        RUNNING,
        PAUSED,
        STOPPED,
        FINISHED
    }

    protected final Logger logger = Logger.getLogger(getClass());

    private int fuzzerScanId;
    private String fuzzerScanName;
    private final FuzzerOptions fuzzerOptions;

    private final M message;
    private final List<
                    ? extends MessageLocationReplacementGenerator<?, MessageLocationReplacement<?>>>
            fuzzLocations;

    private final MultipleMessageLocationsReplacer<M> multipleMessageLocationsReplacer;

    private final List<FuzzerProgressListener> listeners;

    private long tasksIdCounter;
    private final long tasksTotalCount;
    private final AtomicLong tasksDoneCount;

    private final ReentrantLock scannerStateLock;
    private final Condition unpauseCondition;

    private final ExecutorTerminatedListenerImpl executorTerminatedListener;

    private final boolean checkMaxErrorsAllowed;
    private final int maxErrorsAllowed;
    private final AtomicInteger errorCount;

    private State state;

    private PausableExecutorService fuzzerTaskExecutor;

    public AbstractFuzzer(
            String fuzzerScanName,
            FuzzerOptions fuzzerOptions,
            M message,
            List<? extends MessageLocationReplacementGenerator<?, MessageLocationReplacement<?>>>
                    fuzzLocations,
            MultipleMessageLocationsReplacer<M> multipleMessageLocationsReplacer) {
        super();
        if (!multipleMessageLocationsReplacer.isInitialised()) {
            throw new IllegalArgumentException(
                    "MultipleMessageLocationsReplacer is not initialised.");
        }

        this.fuzzerScanId = -1;
        this.fuzzerScanName = fuzzerScanName;
        this.fuzzerOptions = fuzzerOptions;

        this.message = message;
        this.fuzzLocations = fuzzLocations;
        this.multipleMessageLocationsReplacer = multipleMessageLocationsReplacer;

        this.listeners = new ArrayList<>();

        tasksIdCounter = 1;
        tasksDoneCount = new AtomicLong();

        scannerStateLock = new ReentrantLock();
        unpauseCondition = scannerStateLock.newCondition();

        executorTerminatedListener = new ExecutorTerminatedListenerImpl();

        maxErrorsAllowed = getFuzzerOptions().getMaxErrorsAllowed();
        checkMaxErrorsAllowed = (maxErrorsAllowed >= 0);
        errorCount = new AtomicInteger();

        state = State.NOT_STARTED;
        tasksTotalCount = multipleMessageLocationsReplacer.getNumberOfReplacements();
    }

    protected FuzzerOptions getFuzzerOptions() {
        return fuzzerOptions;
    }

    public M getMessage() {
        return message;
    }

    /**
     * Starts the fuzzer.
     *
     * <p>The call to this method has no effect if the scan was already started.
     */
    @Override
    public void run() {
        startScan();
    }

    /**
     * Starts the fuzzer.
     *
     * <p>The call to this method has no effect if the scan was already started.
     */
    public void startScan() {
        acquireScanStateLock();
        try {
            if (State.NOT_STARTED.equals(state)) {
                if (fuzzerScanId == -1) {
                    throw new IllegalStateException("Fuzzer ID was not set.");
                }

                logger.info("Fuzzer started...");
                state = State.RUNNING;

                fuzzerTaskExecutor = createFuzzerTaskExecutor();
                fuzzerTaskExecutor.addExecutorTerminatedListener(executorTerminatedListener);
                createFuzzerTaskSubmitter().start();
            }
        } finally {
            releaseScanStateLock();
        }
    }

    private void acquireScanStateLock() {
        scannerStateLock.lock();
    }

    private void releaseScanStateLock() {
        scannerStateLock.unlock();
    }

    protected PausableExecutorService createFuzzerTaskExecutor() {
        int poolSize = fuzzerOptions.getThreadCount();
        FuzzerThreadFactory threadFactory =
                new FuzzerThreadFactory("ZAP-FuzzerThreadPool-" + fuzzerScanId + "-thread-");

        if (fuzzerOptions.getSendMessageDelay() > 0) {
            PausableScheduledThreadPoolExecutor executor =
                    new PausableScheduledThreadPoolExecutor(poolSize, threadFactory);
            executor.setDefaultDelay(
                    fuzzerOptions.getSendMessageDelay(),
                    fuzzerOptions.getSendMessageDelayTimeUnit());
            executor.setIncrementalDefaultDelay(true);
            return executor;
        }

        return new PausableThreadPoolExecutor(
                poolSize,
                poolSize,
                0L,
                TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<Runnable>(),
                threadFactory);
    }

    protected FuzzerTaskSubmitter createFuzzerTaskSubmitter() {
        return new FuzzerTaskSubmitter(
                "ZAP-FuzzerTaskSubmitter-" + fuzzerScanId, fuzzerOptions.getThreadCount() * 3);
    }

    protected boolean submitFuzzerTask(AbstractFuzzerTask<M> task) {
        if (isStopped()) {
            logger.debug("Submitting task skipped, the Fuzzer is stopped.");
            return false;
        }

        try {
            fuzzerTaskExecutor.execute(task);
            return true;
        } catch (RejectedExecutionException e) {
            postTaskExecution(task.getId(), false);
            logger.warn(
                    "Submitted task was rejected, fuzzer state: [stopped="
                            + isStopped()
                            + ", terminated="
                            + fuzzerTaskExecutor.isTerminated()
                            + "].");
        }
        return false;
    }

    protected abstract AbstractFuzzerTask<M> createFuzzerTask(
            long id, M message, List<Object> payloads);

    /**
     * Pauses the fuzzer.
     *
     * <p>The call to this method has no effect if the fuzzer is not running.
     */
    @Override
    public void pauseScan() {
        acquireScanStateLock();
        try {
            if (State.RUNNING.equals(state)) {
                fuzzerTaskExecutor.pause();
                state = State.PAUSED;
            }
        } finally {
            releaseScanStateLock();
        }
    }

    /**
     * Resumes the fuzzer.
     *
     * <p>The call to this method has no effect if the fuzzer is not paused.
     */
    @Override
    public void resumeScan() {
        acquireScanStateLock();
        try {
            if (resumeScanImpl(state)) {
                state = State.RUNNING;
            }
        } finally {
            releaseScanStateLock();
        }
    }

    private boolean resumeScanImpl(State state) {
        if (State.PAUSED.equals(state)) {
            fuzzerTaskExecutor.resume();
            unpauseCondition.signalAll();
            return true;
        }
        return false;
    }

    /**
     * Stops the fuzzer.
     *
     * <p>The call to this method has no effect if the fuzzer was not yet started or has already
     * finished.
     */
    @Override
    public void stopScan() {
        acquireScanStateLock();
        try {
            if (!State.NOT_STARTED.equals(state)
                    && !State.FINISHED.equals(state)
                    && !State.STOPPED.equals(state)) {
                logger.info("Stopping fuzzer...");
                State previousState = state;
                state = State.STOPPED;

                fuzzerTaskExecutor.shutdown();
                resumeScanImpl(previousState);

                // Temporarily release the lock to allow task threads and listeners to query the
                // state of the fuzzer.
                releaseScanStateLock();
                try {
                    shutdownExecutorNow();
                } finally {
                    acquireScanStateLock();
                }
            }
        } finally {
            releaseScanStateLock();
        }
    }

    protected void shutdownExecutorNow() {
        fuzzerTaskExecutor.shutdownNow();
        try {
            if (!fuzzerTaskExecutor.awaitTermination(2, TimeUnit.SECONDS)) {
                logger.warn(
                        "Failed to await for all fuzzer tasks to stop in the given time (2s)...");
            }
        } catch (InterruptedException ignore) {
            logger.warn("Interrupted while awaiting for all fuzzer tasks to stop...");
        }
        terminated(false);
    }

    private void terminated(boolean successfully) {
        fuzzerTaskExecutor.removeExecutorTerminatedListener(executorTerminatedListener);
        fuzzerTaskExecutor = null;

        acquireScanStateLock();
        try {
            state = State.FINISHED;
        } finally {
            releaseScanStateLock();
        }

        notifyListenersFuzzerCompleted(successfully);

        logger.info(successfully ? "Fuzzer completed." : "Fuzzer stopped.");
    }

    protected void notifyListenersFuzzerCompleted(boolean successfully) {
        for (FuzzerProgressListener l : listeners) {
            l.fuzzerCompleted(fuzzerScanId, fuzzerScanName, successfully);
        }
    }

    @Override
    public boolean isRunning() {
        acquireScanStateLock();
        try {
            return State.RUNNING == state;
        } finally {
            releaseScanStateLock();
        }
    }

    @Override
    public boolean isPaused() {
        acquireScanStateLock();
        try {
            return State.PAUSED == state;
        } finally {
            releaseScanStateLock();
        }
    }

    @Override
    public boolean isStopped() {
        acquireScanStateLock();
        try {
            return (State.FINISHED == state || State.STOPPED == state);
        } finally {
            releaseScanStateLock();
        }
    }

    @Override
    public int getProgress() {
        return (int) tasksDoneCount.get();
    }

    @Override
    public int getMaximum() {
        return (int) tasksTotalCount;
    }

    @Override
    public int getScanId() {
        return fuzzerScanId;
    }

    @Override
    public void setScanId(int id) {
        acquireScanStateLock();
        try {
            if (!State.NOT_STARTED.equals(state)) {
                throw new IllegalStateException("Fuzzer was already started.");
            }
        } finally {
            releaseScanStateLock();
        }
        fuzzerScanId = id;
    }

    @Override
    public String getDisplayName() {
        return fuzzerScanName;
    }

    @Override
    public void setDisplayName(String name) {
        throw new UnsupportedOperationException("Fuzzer display name must no be changed.");
    }

    protected void preTaskExecution(long taskId) {}

    protected void postTaskExecution(long taskId, boolean normalTermination) {
        long done = tasksDoneCount.incrementAndGet();
        notifyListenersFuzzerProgress(done, tasksTotalCount);

        if (!normalTermination) {
            increaseErrorCount(
                    taskId,
                    Constant.messages.getString("fuzz.results.error.unknown.source"),
                    Constant.messages.getString("fuzz.results.error.unknown.message"));
        }
    }

    protected void increaseErrorCount(long taskId, String source, String reason) {
        increaseErrorCount(
                taskId, source, reason, Collections.<MessageLocationReplacement<?>>emptyList());
    }

    protected void increaseErrorCount(
            long taskId,
            String source,
            String reason,
            Collection<MessageLocationReplacement<?>> replacements) {
        int total = errorCount.incrementAndGet();
        boolean maxErrorsReached = isMaxErrorsReached();
        handleError(taskId, source, reason, total, maxErrorsReached, replacements);
        if (maxErrorsReached) {
            stopScan();
        }
    }

    protected boolean isMaxErrorsReached() {
        if (checkMaxErrorsAllowed) {
            return getErrorCount() >= maxErrorsAllowed;
        }
        return false;
    }

    protected void handleError(
            long taskId,
            String source,
            String reason,
            int totalErrors,
            boolean maxErrorsReached,
            Collection<MessageLocationReplacement<?>> replacements) {}

    public int getErrorCount() {
        return errorCount.get();
    }

    @Override
    public void addFuzzerProgressListener(FuzzerProgressListener listener) {
        listeners.add(listener);
    }

    @Override
    public void removeFuzzerProgressListener(FuzzerProgressListener listener) {
        listeners.remove(listener);
    }

    protected List<FuzzerProgressListener> getFuzzerListeners() {
        return listeners;
    }

    protected synchronized void notifyListenersFuzzerProgress(
            long executedTasks, long tasksToExecute) {
        for (FuzzerProgressListener l : listeners) {
            l.fuzzerProgress(fuzzerScanId, fuzzerScanName, executedTasks, tasksToExecute);
        }
    }

    /**
     * Called when the crafting of a fuzzed message throws an {@code InvalidMessageException}.
     *
     * <p>Defaults to call {@code postTaskExecution(boolean)} with parameter as {@code false}.
     *
     * @param taskId the ID of the task
     * @param e the exception thrown while crafting the fuzzed message
     * @param replacements the locations and corresponding payloads used in the crafting
     * @see #postTaskExecution(long, boolean)
     */
    protected void failedToCraftFuzzedMessage(
            long taskId,
            InvalidMessageException e,
            SortedSet<MessageLocationReplacement<?>> replacements) {
        postTaskExecution(taskId, true);
        increaseErrorCount(
                taskId,
                Constant.messages.getString("fuzz.results.error.messageFuzzer.source"),
                e.getLocalizedMessage(),
                replacements);
    }

    protected void failedReplacementInFuzzeMessage(
            long taskId,
            ReplacementException e,
            SortedSet<MessageLocationReplacement<?>> replacements) {
        postTaskExecution(taskId, true);
        String message;
        if (e.getCause() != null) {
            message = e.getCause().getLocalizedMessage();
        } else {
            message = e.getLocalizedMessage();
        }
        increaseErrorCount(
                taskId,
                Constant.messages.getString("fuzz.results.error.messageFuzzer.source"),
                message,
                replacements);
    }

    /**
     * A {@code Thread} responsible to submit fuzzer tasks retrieved from a {@code
     * MultipleMessageLocationsReplacer}.
     *
     * @see AbstractFuzzerTask
     * @see MultipleMessageLocationsReplacer
     */
    private class FuzzerTaskSubmitter extends Thread {

        private final long maxNumberOfLiveTasks;
        private long totalTasksSubmitted;

        public FuzzerTaskSubmitter(String threadName, long maxNumberOfLiveTasks) {
            super(threadName);
            this.maxNumberOfLiveTasks = maxNumberOfLiveTasks;
        }

        @Override
        public void run() {
            try {
                submitTasks();
            } catch (Exception e) {
                logger.error("An exception occurred while fuzzing:", e);
            } finally {
                try {
                    multipleMessageLocationsReplacer.close();
                } catch (Exception e) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Failed to close the message locations replacer:", e);
                    }
                }

                if (fuzzerTaskExecutor != null) {
                    fuzzerTaskExecutor.shutdown();
                }
            }
        }

        private void submitTasks() {
            while (multipleMessageLocationsReplacer.hasNext() && !isStopped()) {
                while ((totalTasksSubmitted - tasksDoneCount.get()) > maxNumberOfLiveTasks
                        && !isStopped()) {
                    try {
                        sleep(25);
                    } catch (InterruptedException ignore) {
                    }
                }

                if (isStopped()) {
                    return;
                }

                boolean taskSubmitted = false;
                do {
                    acquireScanStateLock();
                    try {
                        while (AbstractFuzzer.State.PAUSED == state) {
                            unpauseCondition.await();
                        }
                    } catch (InterruptedException ignore) {
                    } finally {
                        releaseScanStateLock();
                    }

                    if (!isPaused() && !isStopped()) {
                        long taskId = tasksIdCounter++;
                        try {
                            M message = multipleMessageLocationsReplacer.next();
                            submitFuzzerTask(
                                    createFuzzerTask(taskId, message, getCurrentPayloads()));
                        } catch (InvalidMessageException e) {
                            failedToCraftFuzzedMessage(
                                    taskId,
                                    e,
                                    multipleMessageLocationsReplacer.currentReplacements());
                        } catch (ReplacementException e) {
                            failedReplacementInFuzzeMessage(
                                    taskId,
                                    e,
                                    multipleMessageLocationsReplacer.currentReplacements());
                        }
                        taskSubmitted = true;
                        totalTasksSubmitted++;
                    }
                } while (!taskSubmitted && !isStopped());
            }
        }

        protected List<Object> getCurrentPayloads() {
            List<Object> payloads =
                    new ArrayList<>(multipleMessageLocationsReplacer.currentReplacements().size());
            for (MessageLocationReplacement<?> replacement :
                    multipleMessageLocationsReplacer.currentReplacements()) {
                payloads.add(replacement.getReplacement());
            }
            return payloads;
        }
    }

    protected static class FuzzerThreadFactory implements ThreadFactory {

        private final AtomicInteger threadNumber;
        private final String namePrefix;
        private final ThreadGroup group;

        public FuzzerThreadFactory(String namePrefix) {
            threadNumber = new AtomicInteger(1);
            this.namePrefix = namePrefix;
            SecurityManager s = System.getSecurityManager();
            group = (s != null) ? s.getThreadGroup() : Thread.currentThread().getThreadGroup();
        }

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(group, r, namePrefix + threadNumber.getAndIncrement(), 0);
            if (t.isDaemon()) {
                t.setDaemon(false);
            }
            if (t.getPriority() != Thread.NORM_PRIORITY) {
                t.setPriority(Thread.NORM_PRIORITY);
            }
            return t;
        }
    }

    private class ExecutorTerminatedListenerImpl implements ExecutorTerminatedListener {

        @Override
        public void terminated() {
            // Terminate in other thread than one of pool's thread, otherwise it might
            // lead to deadlock (attempting to lock on scannerStateLock) between, for
            // example, EDT and pool's thread, if the scan is stopped just before the
            // termination.
            new Thread(
                            new Runnable() {

                                @Override
                                public void run() {
                                    acquireScanStateLock();
                                    try {
                                        if (!State.FINISHED.equals(state)
                                                && !State.STOPPED.equals(state)) {
                                            AbstractFuzzer.this.terminated(true);
                                        }
                                    } finally {
                                        releaseScanStateLock();
                                    }
                                }
                            },
                            "ZAP-FuzzerTerminationNotifier-" + fuzzerScanId)
                    .start();
        }
    }
}
