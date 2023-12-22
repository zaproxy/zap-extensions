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
package org.zaproxy.addon.client.spider;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.client.ClientMap;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;

public class ClientSpider implements EventConsumer {

    /*
     * Client Spider status - Work In Progress.
     * This functionality has not yet been officially released, so do not rely on any of the classes or methods for now.
     *
     * TODO The following features will need to be implemented before the first release:
     * 		GUI (!)
     * 		Separate proxy (or maybe even one proxy per browser?)
     * 		Support for modes
     * 		Help pages
     *
     * The following features should be implemented in future releases:
     * 		Filling in forms
     * 		Clicking on buttons
     * 		Clicking on likely navigation elements
     * 		Preventing reqs to out of scope sites (via navigation elements)
     * 		Automation framework support
     * 		API support
     */
    private static final Logger LOGGER = LogManager.getLogger(ClientSpider.class);

    private static final int SHUTDOWN_SLEEP_INTERVAL = 200;

    private ExecutorService threadPool;

    private int id;
    private ClientOptions options;

    private String targetUrl;
    private ExtensionSelenium extSelenium;

    private List<WebDriver> webDriverPool = new ArrayList<>();
    private Set<WebDriver> webDriverActive = new HashSet<>();
    private List<ClientSpiderTask> spiderTasks = new ArrayList<>();
    private List<ClientSpiderTask> pausedTasks = new ArrayList<>();
    private long startTime;
    private long lastEventReceivedtime;
    private long maxTime;
    private boolean paused;
    private boolean finished;
    private boolean stopped;

    private int tasksDoneCount;
    private int tasksTotalCount;

    public ClientSpider(String targetUrl, ClientOptions options, int id) {
        this.targetUrl = targetUrl;
        this.options = options;
        this.id = id;
        ZAP.getEventBus().registerConsumer(this, ClientMap.class.getCanonicalName());

        extSelenium =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
    }

    public void start() {
        startTime = System.currentTimeMillis();
        lastEventReceivedtime = startTime;
        if (options.getMaxDuration() > 0) {
            maxTime = startTime + TimeUnit.MINUTES.toMillis(options.getMaxDuration());
        }

        this.threadPool =
                Executors.newFixedThreadPool(
                        options.getThreadCount(),
                        new ClientSpiderThreadFactory(
                                "ZAP-ClientSpiderThreadPool-" + id + "-thread-"));

        addTask(targetUrl, options.getInitialLoadTimeInSecs());
    }

    public synchronized WebDriver getWebDriver() {
        WebDriver wd;
        synchronized (this.webDriverPool) {
            if (!this.webDriverPool.isEmpty()) {
                wd = this.webDriverPool.remove(0);
            } else {
                wd = extSelenium.getProxiedBrowser(options.getBrowserId(), targetUrl);
            }
            this.webDriverActive.add(wd);
        }
        return wd;
    }

    public void returnWebDriver(WebDriver wd) {
        // Deliberately synchronized on webDriverPool as they are modified together
        synchronized (this.webDriverPool) {
            this.webDriverActive.remove(wd);
            this.webDriverPool.add(wd);
        }
    }

    private void addTask(String url, int loadTimeInSecs) {
        this.tasksTotalCount++;
        try {
            ClientSpiderTask task = new ClientSpiderTask(this, url, loadTimeInSecs);
            if (paused) {
                this.pausedTasks.add(task);
            } else {
                executeTask(task);
            }
        } catch (RejectedExecutionException e) {
            tempLogProgress("Failed to add task: " + e.getMessage());
        }
    }

    private void executeTask(ClientSpiderTask task) {
        this.spiderTasks.add(task);
        this.threadPool.execute(task);
    }

    protected synchronized void postTaskExecution(ClientSpiderTask task) {
        this.tasksDoneCount++;
        this.spiderTasks.remove(task);
        if (this.spiderTasks.isEmpty()) {
            this.tempLogProgress("No running tasks, starting shutdown timer");
            new ShutdownThread(options.getShutdownTimeInSecs()).start();
        }
    }

    @Override
    public void eventReceived(Event event) {
        if (finished) {
            return;
        }
        this.lastEventReceivedtime = System.currentTimeMillis();
        if (maxTime > 0 && this.lastEventReceivedtime > maxTime) {
            this.tempLogProgress("Exceeded max time, stopping");
            this.stop();
            return;
        }

        String url = event.getParameters().get(ClientMap.URL_KEY);
        if (url.startsWith(targetUrl)) {
            if (options.getMaxDepth() > 0) {
                int depth = Integer.parseInt(event.getParameters().get(ClientMap.DEPTH_KEY));
                if (depth > options.getMaxDepth()) {
                    LOGGER.debug(
                            "Ignoring URL - too deep {} > {} : {}",
                            depth,
                            options.getMaxDepth(),
                            url);
                    return;
                }
            }
            if (options.getMaxChildren() > 0) {
                int siblings = Integer.parseInt(event.getParameters().get(ClientMap.SIBLINGS_KEY));
                if (siblings > options.getMaxChildren()) {
                    LOGGER.debug(
                            "Ignoring URL - too wide {} > {} : {}",
                            siblings,
                            options.getMaxChildren(),
                            url);
                    return;
                }
            }
            addTask(url, options.getPageLoadTimeInSecs());
        }
    }

    public int getProgress() {
        if (finished & !stopped) {
            return 100;
        } else if (this.tasksTotalCount <= 1) {
            // Still waiting for the first request to be processed
            return 0;
        }
        return (this.tasksDoneCount * 100) / this.tasksTotalCount;
    }

    public void stop() {
        this.stopped = true;
        if (paused) {
            this.pausedTasks.clear();
            this.paused = false;
        }
        finished();
        ZAP.getEventBus().unregisterConsumer(this, ClientMap.class.getCanonicalName());
    }

    public void pause() {
        this.paused = true;
    }

    public void resume() {
        this.pausedTasks.forEach(ct -> executeTask(ct));
        this.paused = false;
    }

    protected boolean isStopped() {
        return stopped;
    }

    public boolean isPaused() {
        return paused;
    }

    public boolean isRunning() {
        return !finished;
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    /**
     * TODO This is a temporary method used to record progress. It will be removed once the GUI has
     * been implemented. Messages are not expected to be i18n'ed.
     */
    protected void tempLogProgress(String msg) {
        if (View.isInitialised()) {
            View.getSingleton().getOutputPanel().appendAsync(msg + "\n");
        } else {
            LOGGER.debug(msg);
        }
    }

    private void finished() {
        finished = true;
        long timeTaken = System.currentTimeMillis() - startTime;
        tempLogProgress(
                "Spider finished " + DurationFormatUtils.formatDuration(timeTaken, "HH:MM:SS"));
        synchronized (this.webDriverPool) {
            for (WebDriver wd : this.webDriverPool) {
                wd.quit();
            }
            this.webDriverPool.clear();
            for (WebDriver wd : this.webDriverActive) {
                wd.quit();
            }
            this.webDriverActive.clear();
        }
    }

    private class ShutdownThread extends Thread {

        private int timeoutInSecs;
        private long starttime;

        ShutdownThread(int timeoutInSecs) {
            this.timeoutInSecs = timeoutInSecs;
            this.starttime = System.currentTimeMillis();
        }

        @Override
        public void run() {
            for (int i = 0; i < (timeoutInSecs * 1000) / SHUTDOWN_SLEEP_INTERVAL; i++) {
                try {
                    sleep(SHUTDOWN_SLEEP_INTERVAL);
                } catch (InterruptedException e) {
                    // Ignore
                }
                if (lastEventReceivedtime > starttime) {
                    // New event, don't shutdown
                    tempLogProgress("Spider not finished..");
                    if (spiderTasks.isEmpty()) {
                        tempLogProgress("No running tasks, restarting shutdown timer");
                        new ShutdownThread(options.getShutdownTimeInSecs()).start();
                    }
                    return;
                }
            }
            // No new client event in the shutdown period
            finished();
        }
    }

    private static class ClientSpiderThreadFactory implements ThreadFactory {

        private final AtomicInteger threadNumber;
        private final String namePrefix;
        private final ThreadGroup group;

        ClientSpiderThreadFactory(String namePrefix) {
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
}
