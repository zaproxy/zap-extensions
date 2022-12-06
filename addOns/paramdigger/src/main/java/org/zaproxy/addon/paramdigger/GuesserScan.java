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
package org.zaproxy.addon.paramdigger;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import org.zaproxy.addon.paramdigger.gui.ParamDiggerHistoryTableModel;
import org.zaproxy.zap.model.GenericScanner2;

public class GuesserScan implements GenericScanner2 {
    private static enum State {
        NOT_STARTED,
        RUNNING,
        PAUSED,
        STOPPED,
        FINISHED
    }

    private final Lock lock;
    private int scanId;
    private State state;

    private String displayName;
    private ParamDiggerConfig config;

    private int tasksDoneCount;
    private int tasksTodoCount;

    private final ExecutorService executor;
    private final List<GuesserProgressListener> listeners;
    private final ParamDiggerHistoryTableModel tableModel;
    private List<ParamGuessResult> results;
    private OutputModel outputModel;

    public GuesserScan(int scanId, ParamDiggerConfig config, String name) {
        this.scanId = scanId;
        this.displayName = name;
        this.lock = new ReentrantLock();
        this.state = State.NOT_STARTED;
        this.config = config;

        listeners = new ArrayList<>(2);
        tableModel = new ParamDiggerHistoryTableModel();
        results = Collections.synchronizedList(new ArrayList<>());
        this.executor =
                Executors.newFixedThreadPool(
                        config.getThreadCount(),
                        new ParamGuesserThreadFactory("ZAP-ParamGuesser-" + scanId + "-thread-"));
    }

    public void addProgressListener(GuesserProgressListener listener) {
        listeners.add(listener);
    }

    public ParamDiggerHistoryTableModel getTableModel() {
        return tableModel;
    }

    public ParamDiggerConfig getConfig() {
        return config;
    }

    @Override
    public void run() {}

    @Override
    public void setScanId(int id) {
        this.scanId = id;
    }

    @Override
    public int getScanId() {
        return scanId;
    }

    public OutputModel getOutputModel() {
        if (outputModel == null) {
            outputModel = new OutputModel();
        }
        return outputModel;
    }

    public String getState() {
        lock.lock();
        try {
            return state.toString();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void setDisplayName(String name) {
        this.displayName = name;
    }

    @Override
    public String getDisplayName() {
        return this.displayName;
    }

    public void start() {
        lock.lock();
        try {
            if (state == State.NOT_STARTED) {
                state = State.RUNNING;
                startScan();
            }
        } finally {
            lock.unlock();
        }
    }

    private void startScan() {
        ParamGuesser paramGuesser = new ParamGuesser(scanId, this, this.executor);
        this.executor.submit(paramGuesser);
    }

    void completed() {
        lock.lock();
        try {
            state = State.FINISHED;
            new Thread(
                            () -> {
                                executor.shutdown();
                                notifyListenersCompleted(true);
                            },
                            "ZAP-ParamGuesserShutdownThread-" + this.scanId)
                    .start();
        } finally {
            lock.unlock();
        }
    }

    private void notifyListenersCompleted(boolean successfully) {
        for (GuesserProgressListener listener : listeners) {
            listener.completed(scanId, displayName, successfully);
        }
    }

    synchronized void notifyListenersProgress() {
        tasksDoneCount++;

        for (GuesserProgressListener listener : listeners) {
            listener.updateProgress(scanId, displayName, tasksDoneCount, tasksTodoCount);
        }
    }

    @Override
    public void stopScan() {
        lock.lock();
        try {
            if (state != State.NOT_STARTED && state != State.FINISHED) {
                state = State.FINISHED;

                notifyListenersCompleted(false);
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public boolean isStopped() {
        lock.lock();
        try {
            return state == State.FINISHED || state == State.STOPPED;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public int getProgress() {
        return tasksDoneCount;
    }

    @Override
    public int getMaximum() {
        return tasksTodoCount;
    }

    void setMaximum(int max) {
        tasksTodoCount = tasksTodoCount + max;
    }

    @Override
    public void pauseScan() {
        lock.lock();
        try {
            if (state == State.RUNNING) {
                state = State.PAUSED;
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void resumeScan() {
        lock.lock();
        try {
            if (state == State.PAUSED) {
                state = State.RUNNING;
            }
        } finally {
            lock.unlock();
        }
    }

    @Override
    public boolean isPaused() {
        lock.lock();
        try {
            return state == State.PAUSED;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public boolean isRunning() {
        lock.lock();
        try {
            return state == State.RUNNING;
        } finally {
            lock.unlock();
        }
    }

    public void clear() {}

    private static class ParamGuesserThreadFactory implements ThreadFactory {

        private final AtomicInteger threadNumber;
        private final String namePrefix;
        private final ThreadGroup group;

        public ParamGuesserThreadFactory(String namePrefix) {
            threadNumber = new AtomicInteger(1);
            this.namePrefix = namePrefix;
            group = Thread.currentThread().getThreadGroup();
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

    public void setProgress(int maximum) {
        this.tasksDoneCount = maximum;
    }

    public void addParamGuessResult(ParamGuessResult paramGuessResult) {
        this.results.add(paramGuessResult);
        if (outputModel != null) {
            outputModel.notifyResult(paramGuessResult);
        }
    }

    public List<ParamGuessResult> getResults() {
        return results;
    }
}
