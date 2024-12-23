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
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import javax.swing.table.TableModel;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ClientMap;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.client.spider.actions.ClickElement;
import org.zaproxy.addon.client.spider.actions.OpenUrl;
import org.zaproxy.addon.client.spider.actions.SubmitForm;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.model.GenericScanner2;
import org.zaproxy.zap.model.ScanListenner2;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.ThreadUtils;

public class ClientSpider implements EventConsumer, GenericScanner2 {

    /*
     * Client Spider status - Work In Progress.
     * This functionality has not yet been officially released, so do not rely on any of the classes or methods for now.
     *
     * TODO The following features will need to be implemented before the first release:
     * 		Separate proxy (or maybe even one proxy per browser?)
     * 		Support for modes
     * 		Help pages
     *
     * The following features should be implemented in future releases:
     * 		Clicking on likely navigation elements
     * 		Preventing reqs to out of scope sites (via navigation elements)
     * 		Automation framework support
     * 		API support
     */
    private static final Logger LOGGER = LogManager.getLogger(ClientSpider.class);

    private static final int SHUTDOWN_SLEEP_INTERVAL = 200;

    private ExecutorService threadPool;

    private final ValueProvider valueProvider;
    private ClientOptions options;
    private int scanId;
    private String displayName;

    private String targetUrl;
    private User user;
    private ExtensionClientIntegration extClient;
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
    private final AtomicInteger tasksTotalCount;

    private UrlTableModel addedNodesModel;
    private TaskTableModel tasksModel;
    private ScanListenner2 listener;

    public ClientSpider(
            ExtensionClientIntegration extClient,
            String displayName,
            String targetUrl,
            ClientOptions options,
            int id,
            User user,
            ValueProvider valueProvider) {
        this.extClient = extClient;
        this.displayName = displayName;
        this.targetUrl = targetUrl;
        this.options = options;
        this.scanId = id;
        this.tasksTotalCount = new AtomicInteger();
        this.user = user;
        this.valueProvider = valueProvider;
        this.addedNodesModel = new UrlTableModel();
        this.tasksModel = new TaskTableModel();

        ZAP.getEventBus().registerConsumer(this, ClientMap.class.getCanonicalName());

        extSelenium =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionSelenium.class);
    }

    public ClientSpider(
            ExtensionClientIntegration extClient,
            String displayName,
            String targetUrl,
            ClientOptions options,
            int id) {
        this(extClient, displayName, targetUrl, options, id, null, null);
    }

    @Override
    public void run() {
        startTime = System.currentTimeMillis();
        lastEventReceivedtime = startTime;
        if (options.getMaxDuration() > 0) {
            maxTime = startTime + TimeUnit.MINUTES.toMillis(options.getMaxDuration());
        }
        if (user != null) {
            synchronized (this.extClient.getAuthenticationHandlers()) {
                this.extClient
                        .getAuthenticationHandlers()
                        .forEach(handler -> handler.enableAuthentication(user));
            }
        }

        this.threadPool =
                Executors.newFixedThreadPool(
                        options.getThreadCount(),
                        new ClientSpiderThreadFactory(
                                "ZAP-ClientSpiderThreadPool-" + scanId + "-thread-"));

        List<String> unvisitedUrls = getUnvisitedUrls();

        addInitialOpenUrlTask(targetUrl);

        // Add all of the known but unvisited URLs otherwise these will get ignored
        unvisitedUrls.forEach(this::addInitialOpenUrlTask);
    }

    private ClientSpiderTask addInitialOpenUrlTask(String url) {
        return addOpenUrlTask(url, options.getInitialLoadTimeInSecs());
    }

    private ClientSpiderTask addOpenUrlTask(String url, int loadTimeInSecs) {
        return addTask(
                url,
                openAction(url),
                loadTimeInSecs,
                Constant.messages.getString("client.spider.panel.table.action.get"),
                "");
    }

    private List<SpiderAction> openAction(String url, SpiderAction... additionalActions) {
        List<SpiderAction> actions = new ArrayList<>(5);
        actions.add(new OpenUrl(url));
        actions.add(wd -> checkRedirect(url, wd));
        if (additionalActions != null) {
            Stream.of(additionalActions).forEach(actions::add);
        }
        return actions;
    }

    private void checkRedirect(String url, WebDriver wd) {
        String actualUrl = wd.getCurrentUrl();
        if (!url.equals(actualUrl)) {
            setRedirect(url, actualUrl);
        }
    }

    private List<String> getUnvisitedUrls() {
        List<String> urls = new ArrayList<>();
        ClientNode targetNode = extClient.getClientNode(targetUrl, false, false);
        if (targetUrl.endsWith("/") && targetNode != null) {
            // Start up one level as "/" will be a leaf node
            getUnvisitedUrls(targetNode.getParent(), urls);
        }

        return urls;
    }

    private void getUnvisitedUrls(ClientNode node, List<String> urls) {
        String nodeUrl = node.getUserObject().getUrl();
        if (nodeUrl.startsWith(targetUrl)
                && nodeUrl.length() != targetUrl.length()
                && !node.isStorage()
                && !node.getUserObject().isVisited()) {
            urls.add(nodeUrl);
        }
        for (int i = 0; i < node.getChildCount(); i++) {
            getUnvisitedUrls(node.getChildAt(i), urls);
        }
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

    private ClientSpiderTask addTask(
            String url,
            List<SpiderAction> actions,
            int loadTimeInSecs,
            String displayName,
            String detailsString) {
        int id = tasksTotalCount.incrementAndGet();
        try {
            ClientSpiderTask task =
                    new ClientSpiderTask(
                            id, this, actions, loadTimeInSecs, displayName, detailsString);
            this.addTaskToTasksModel(task, url);
            if (paused) {
                this.pausedTasks.add(task);
            } else {
                executeTask(task);
            }
            return task;
        } catch (RejectedExecutionException e) {
            LOGGER.debug("Failed to add task", e.getMessage());
        }
        return null;
    }

    private void executeTask(ClientSpiderTask task) {
        this.spiderTasks.add(task);
        this.threadPool.execute(task);
    }

    protected synchronized void postTaskExecution(ClientSpiderTask task) {
        this.tasksDoneCount++;
        this.spiderTasks.remove(task);
        if (listener != null) {
            listener.scanProgress(scanId, displayName, this.getProgress(), this.getMaximum());
        }
        if (this.spiderTasks.isEmpty() && !paused) {
            LOGGER.debug("No running tasks, starting shutdown timer");
            new ShutdownThread(options.getShutdownTimeInSecs()).start();
        }
    }

    @Override
    public void eventReceived(Event event) {
        if (finished || stopped) {
            return;
        }
        this.lastEventReceivedtime = System.currentTimeMillis();
        if (maxTime > 0 && this.lastEventReceivedtime > maxTime) {
            LOGGER.debug("Exceeded max time, stopping");
            this.stopScan();
            return;
        }

        Map<String, String> parameters = event.getParameters();
        String url = parameters.get(ClientMap.URL_KEY);
        if (url.startsWith(targetUrl)) {
            addUriToAddedNodesModel(url);

            if (options.getMaxDepth() > 0) {
                int depth = Integer.parseInt(parameters.get(ClientMap.DEPTH_KEY));
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
                int siblings = Integer.parseInt(parameters.get(ClientMap.SIBLINGS_KEY));
                if (siblings > options.getMaxChildren()) {
                    LOGGER.debug(
                            "Ignoring URL - too wide {} > {} : {}",
                            siblings,
                            options.getMaxChildren(),
                            url);
                    return;
                }
            }

            if (ClientMap.MAP_COMPONENT_ADDED_EVENT.equals(event.getEventType())) {
                if (ClickElement.isSupported(href -> href.startsWith(targetUrl), parameters)) {
                    addTask(
                            url,
                            openAction(
                                    url,
                                    new ClickElement(valueProvider, createURI(url), parameters)),
                            options.getPageLoadTimeInSecs(),
                            Constant.messages.getString("client.spider.panel.table.action.click"),
                            paramsToString(parameters));
                } else if (SubmitForm.isSupported(parameters)) {
                    addTask(
                            url,
                            openAction(
                                    url, new SubmitForm(valueProvider, createURI(url), parameters)),
                            options.getPageLoadTimeInSecs(),
                            Constant.messages.getString("client.spider.panel.table.action.submit"),
                            paramsToString(parameters));
                }
            } else {
                addOpenUrlTask(url, options.getPageLoadTimeInSecs());
            }
        }
    }

    private static String paramsToString(Map<String, String> parameters) {
        String tag = parameters.get("tagName");
        if (tag != null) {
            switch (tag) {
                case "A":
                    return Constant.messages.getString(
                            "client.spider.panel.table.details.link",
                            parameters.get("href"),
                            parameters.get("text"));
                case "BUTTON":
                    return Constant.messages.getString(
                            "client.spider.panel.table.details.button", parameters.get("text"));
            }
        }
        return parameters.toString();
    }

    private URI createURI(String value) {
        try {
            return new URI(value, true);
        } catch (URIException | NullPointerException e) {
            LOGGER.warn("Failed to create URI from {}", value, e);
        }
        return null;
    }

    private void addUriToAddedNodesModel(final String uri) {
        ThreadUtils.invokeLater(
                () -> {
                    addedNodesModel.addScanResult(uri);
                    extClient.updateAddedCount();
                });
    }

    public void taskStateChange(final ClientSpiderTask task) {
        ThreadUtils.invokeLater(
                () ->
                        tasksModel.updateTaskState(
                                task.getId(), task.getStatus().toString(), task.getError()));
    }

    private void addTaskToTasksModel(final ClientSpiderTask task, String url) {
        ThreadUtils.invokeLater(
                () ->
                        tasksModel.addTask(
                                task.getId(),
                                task.getDisplayName(),
                                url,
                                task.getDetailsString(),
                                task.getStatus().toString()));
    }

    protected void setRedirect(String originalUrl, String redirectedUrl) {
        ThreadUtils.invokeLater(() -> extClient.setRedirect(originalUrl, redirectedUrl));
    }

    @Override
    public int getProgress() {
        if (finished && !stopped) {
            return 100;
        } else if (tasksTotalCount.get() <= 1) {
            // Still waiting for the first request to be processed
            return 0;
        }
        return (this.tasksDoneCount * 100) / tasksTotalCount.get();
    }

    @Override
    public void stopScan() {
        this.stopped = true;
        if (paused) {
            this.pausedTasks.clear();
            this.paused = false;
        }
        finished();
        ZAP.getEventBus().unregisterConsumer(this, ClientMap.class.getCanonicalName());
    }

    @Override
    public void pauseScan() {
        this.paused = true;
    }

    @Override
    public void resumeScan() {
        this.pausedTasks.forEach(this::executeTask);
        this.paused = false;
    }

    @Override
    public boolean isStopped() {
        return finished || stopped;
    }

    @Override
    public boolean isPaused() {
        return paused;
    }

    @Override
    public boolean isRunning() {
        return !finished;
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    private void finished() {
        finished = true;
        long timeTaken = System.currentTimeMillis() - startTime;
        LOGGER.debug(
                "Spider finished {}", DurationFormatUtils.formatDuration(timeTaken, "HH:MM:SS"));
        if (this.user != null) {
            synchronized (extClient.getAuthenticationHandlers()) {
                extClient
                        .getAuthenticationHandlers()
                        .forEach(handler -> handler.disableAuthentication(user));
            }
        }
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
        if (listener != null) {
            listener.scanFinshed(scanId, displayName);
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
                    LOGGER.debug("Spider not finished..");
                    if (spiderTasks.isEmpty()) {
                        LOGGER.debug("No running tasks, restarting shutdown timer");
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

    @Override
    public void setScanId(int id) {
        this.scanId = id;
    }

    @Override
    public int getScanId() {
        return this.scanId;
    }

    @Override
    public void setDisplayName(String name) {
        this.displayName = name;
    }

    @Override
    public String getDisplayName() {
        return this.displayName;
    }

    @Override
    public int getMaximum() {
        return 100;
    }

    public TableModel getAddedNodesTableModel() {
        return this.addedNodesModel;
    }

    public TableModel getActionsTableModel() {
        return this.tasksModel;
    }

    public void setListener(ScanListenner2 listener) {
        this.listener = listener;
    }
}
