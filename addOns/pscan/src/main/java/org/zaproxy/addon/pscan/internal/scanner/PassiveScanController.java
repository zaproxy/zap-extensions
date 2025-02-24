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
package org.zaproxy.addon.pscan.internal.scanner;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;
import org.zaproxy.addon.pscan.internal.PassiveScannerOptions;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.pscan.PassiveScanData;
import org.zaproxy.zap.extension.pscan.PassiveScanner;
import org.zaproxy.zap.utils.Stats;

public class PassiveScanController extends Thread {

    private static final Logger LOGGER = LogManager.getLogger(PassiveScanController.class);

    private Constructor<PassiveScanData> pscanDataConstructor;
    private Consumer<PassiveScanner> setPscanActions;

    private ExtensionHistory extHist;
    private PassiveScanTaskHelper helper;
    private Session session;

    private ThreadPoolExecutor executor;

    private int currentId = 1;
    private int lastId = -1;
    private int mainSleep = 2000;
    private int postSleep = 200;
    private volatile boolean shutDown = false;

    public PassiveScanController(
            ExtensionPassiveScan2 extPscan, ExtensionHistory extHistory, ExtensionAlert extAlert) {
        setName("ZAP-PassiveScanController");
        this.extHist = extHistory;

        helper = new PassiveScanTaskHelper(extPscan, extAlert);

        // Get the last id - in case we've just opened an existing session
        currentId = getLastHistoryId();
        lastId = currentId;

        try {
            pscanDataConstructor = PassiveScanData.class.getConstructor(HttpMessage.class);
        } catch (Exception e) {
            // Ignore, the constructor exists but was previously not visible.
        }

        try {
            InvocationHandler invocationHandler =
                    (o, method, args) -> {
                        switch (method.getName()) {
                            case "addHistoryTag":
                                helper.addHistoryTag((HistoryReference) args[0], (String) args[1]);
                                return null;

                            case "raiseAlert":
                                helper.raiseAlert((HistoryReference) args[0], (Alert) args[1]);
                                return null;

                            default:
                                return null;
                        }
                    };

            Class<?> clazz =
                    org.zaproxy.zap.extension.pscan.ExtensionPassiveScan.class
                            .getClassLoader()
                            .loadClass("org.zaproxy.zap.extension.pscan.PassiveScanActions");
            Method setPassiveScanActions =
                    org.zaproxy.zap.extension.pscan.PassiveScanner.class.getDeclaredMethod(
                            "setPassiveScanActions", clazz);
            Object passiveScanActions =
                    Proxy.newProxyInstance(
                            clazz.getClassLoader(), new Class<?>[] {clazz}, invocationHandler);

            setPscanActions =
                    scanRule -> {
                        try {
                            setPassiveScanActions.invoke(scanRule, passiveScanActions);
                        } catch (Exception e) {
                            // New core method exists.
                        }
                    };

        } catch (Exception e) {
            LOGGER.error("Failed to create PassiveScanActions:", e);
        }
    }

    public void setSession(Session session) {
        this.session = session;
    }

    @Override
    public void run() {
        LOGGER.debug("Starting passive scan monitoring");
        try {
            scan();
        } finally {
            LOGGER.debug("Stopping passive scan monitoring");
        }
    }

    private void scan() {
        // Get the last id - in case we've just opened an existing session
        currentId = this.getLastHistoryId();
        lastId = currentId;

        // Prevent re-scanning of existing message.
        if (currentId != 0) {
            currentId++;
        }
        HistoryReference href = null;

        while (!shutDown) {
            try {
                if (href != null || lastId > currentId) {
                    currentId++;
                } else {
                    // Either just started or there are no new records
                    try {
                        Thread.sleep(mainSleep);
                        if (shutDown) {
                            return;
                        }
                    } catch (InterruptedException e) {
                        // New URL, but give it a chance to be processed first
                        try {
                            Thread.sleep(postSleep);
                        } catch (InterruptedException e2) {
                            // Ignore
                        }
                    }
                    lastId = this.getLastHistoryId();
                }
                href = getHistoryReference(currentId);

                if (shutDown) {
                    return;
                }

                if (href != null
                        && (!getOptions().isScanOnlyInScope() || session.isInScope(href))) {
                    LOGGER.debug(
                            "Submitting request to executor: {} id {} type {}",
                            href.getURI(),
                            currentId,
                            href.getHistoryType());
                    getExecutor()
                            .submit(
                                    new PassiveScanTask(
                                            href, helper, pscanDataConstructor, setPscanActions));
                }
                int recordsToScan = this.getRecordsToScan();
                Stats.setHighwaterMark("stats.pscan.recordsToScan", recordsToScan);

            } catch (Exception e) {
                if (shutDown) {
                    return;
                }
                if (href != null
                        && HistoryReference.getTemporaryTypes().contains(href.getHistoryType())) {
                    LOGGER.debug("Temporary record {} no longer available:", currentId, e);
                } else {
                    LOGGER.error("Failed on record {} from History table", currentId, e);
                }
            }
        }
    }

    private PassiveScannerOptions getOptions() {
        return extHist.getModel().getOptionsParam().getParamSet(PassiveScannerOptions.class);
    }

    private ThreadPoolExecutor getExecutor() {
        if (this.executor == null || this.executor.isShutdown()) {
            int threads = getOptions().getPassiveScanThreads();
            LOGGER.debug("Creating new executor with {} threads", threads);

            this.executor =
                    (ThreadPoolExecutor)
                            Executors.newFixedThreadPool(
                                    threads, new PassiveScanThreadFactory("ZAP-PassiveScan-"));
        }
        return this.executor;
    }

    private HistoryReference getHistoryReference(final int historyReferenceId) {
        if (extHist != null) {
            return extHist.getHistoryReference(historyReferenceId);
        }

        try {
            return new HistoryReference(historyReferenceId);
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            return null;
        }
    }

    private int getLastHistoryId() {
        return this.extHist.getLastHistoryId();
    }

    public int getRecordsToScan() {
        return this.getLastHistoryId() - getLastScannedId() + helper.getRunningTasks().size();
    }

    private int getLastScannedId() {
        if (currentId > lastId) {
            return currentId - 1;
        }
        return currentId;
    }

    public void shutdown() {
        LOGGER.debug("Shutdown");
        this.shutDown = true;
        if (this.executor != null) {
            this.executor.shutdown();
        }
        this.helper.shutdownTasks();
    }

    public List<PassiveScanTask> getRunningTasks() {
        return this.helper.getRunningTasks();
    }

    public PassiveScanTask getOldestRunningTask() {
        return this.helper.getOldestRunningTask();
    }

    public void clearQueue() {
        currentId = this.getLastHistoryId();
        lastId = currentId;
        this.helper.shutdownTasks();
    }

    public void responseReceived() {
        this.interrupt();
    }

    private static class PassiveScanThreadFactory implements ThreadFactory {

        private final AtomicInteger threadNumber;
        private final String namePrefix;
        private final ThreadGroup group;

        public PassiveScanThreadFactory(String namePrefix) {
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
            if (t.getPriority() != Thread.NORM_PRIORITY - 1) {
                t.setPriority(Thread.NORM_PRIORITY - 1);
            }
            return t;
        }
    }
}
