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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import javax.swing.table.TableModel;
import lombok.Getter;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.client.ClientOptions;
import org.zaproxy.addon.client.ClientOptions.ScopeCheck;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ClientMap;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.client.internal.ClientSideDetails;
import org.zaproxy.addon.client.spider.actions.ClickElement;
import org.zaproxy.addon.client.spider.actions.OpenUrl;
import org.zaproxy.addon.client.spider.actions.SubmitForm;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.addon.network.server.HttpServerConfig;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventConsumer;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.GenericScanner2;
import org.zaproxy.zap.model.ScanListenner2;
import org.zaproxy.zap.network.HttpResponseBody;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.ThreadUtils;

public class ClientSpider implements EventConsumer, GenericScanner2 {

    /*
     * Client Spider status - Work In Progress.
     * This functionality has not yet been officially released, so do not rely on any of the classes or methods for now.
     *
     * TODO The following features will need to be implemented before the first release:
     * 		Support for modes
     *
     * The following features should be implemented in future releases:
     * 		Clicking on likely navigation elements
     * 		API support
     */
    private static final Logger LOGGER = LogManager.getLogger(ClientSpider.class);

    private final List<Pattern> allowedResources =
            List.of(
                    Pattern.compile("^http.*\\.js(?:\\?.*)?$"),
                    Pattern.compile("^http.*\\.css(?:\\?.*)?$"));

    private static HttpResponseHeader outOfScopeResponseHeader;
    private static HttpResponseBody outOfScopeResponseBody;

    public enum ResourceState {
        ALLOWED,
        THIRD_PARTY,
        EXCLUDED,
        IO_ERROR,
        OUT_OF_CONTEXT,
        OUT_OF_HOST,
        OUT_OF_SUBTREE,
    }

    private static final int SHUTDOWN_SLEEP_INTERVAL = 200;

    private ExecutorService threadPool;

    private final ValueProvider valueProvider;
    private ClientOptions options;
    private int scanId;
    private String displayName;

    private String targetUrl;
    private final String targetHost;
    private final HttpPrefixUriValidator httpPrefixUriValidator;
    private final Context context;
    private final User user;
    private ExtensionClientIntegration extClient;
    private final ExtensionSelenium extSelenium;
    private final ExtensionNetwork extensionNetwork;

    private final Session session;
    private final List<String> exclusionList;

    private List<WebDriverProcess> webDriverPool = new ArrayList<>();
    private Set<WebDriverProcess> webDriverActive = new HashSet<>();
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
    private final MessagesTableModel messagesTableModel;
    private final Set<String> crawledUrls;
    private ScanListenner2 listener;

    public ClientSpider(
            ExtensionClientIntegration extClient,
            String displayName,
            String targetUrl,
            ClientOptions options,
            int id,
            Context context,
            User user,
            boolean subtreeOnly,
            ValueProvider valueProvider) {
        this.extClient = extClient;
        session = extClient.getModel().getSession();
        this.displayName = displayName;
        this.targetUrl = targetUrl;
        URI targetUri = createUri(targetUrl);
        targetHost = new String(targetUri.getRawHost());
        this.options = options;
        this.scanId = id;
        this.tasksTotalCount = new AtomicInteger();
        this.context = context;
        this.user = user;
        this.valueProvider = valueProvider;
        this.addedNodesModel = new UrlTableModel();
        this.tasksModel = new TaskTableModel();
        messagesTableModel = new MessagesTableModel();
        crawledUrls = Collections.synchronizedSet(new TreeSet<>());

        ZAP.getEventBus().registerConsumer(this, ClientMap.class.getCanonicalName());

        extSelenium = getExtension(ExtensionSelenium.class);
        extensionNetwork = getExtension(ExtensionNetwork.class);

        exclusionList = new ArrayList<>();
        exclusionList.addAll(session.getExcludeFromSpiderRegexs());
        exclusionList.addAll(session.getGlobalExcludeURLRegexs());

        HttpPrefixUriValidator validator =
                subtreeOnly ? new HttpPrefixUriValidator(targetUri) : null;
        this.httpPrefixUriValidator = validator;
        createOutOfScopeResponse(Constant.messages.getString("client.spider.outofscope.response"));
    }

    private static <T extends Extension> T getExtension(Class<T> clazz) {
        return Control.getSingleton().getExtensionLoader().getExtension(clazz);
    }

    private void createOutOfScopeResponse(String response) {
        outOfScopeResponseBody = new HttpResponseBody();
        outOfScopeResponseBody.setBody(response.getBytes(StandardCharsets.UTF_8));

        final StringBuilder strBuilder = new StringBuilder(150);
        final String crlf = HttpHeader.CRLF;
        strBuilder.append("HTTP/1.1 403 Forbidden").append(crlf);
        strBuilder.append(HttpHeader.PRAGMA).append(": ").append("no-cache").append(crlf);
        strBuilder.append(HttpHeader.CACHE_CONTROL).append(": ").append("no-cache").append(crlf);
        strBuilder
                .append(HttpHeader.CONTENT_TYPE)
                .append(": ")
                .append("text/plain; charset=UTF-8")
                .append(crlf);
        strBuilder
                .append(HttpHeader.CONTENT_LENGTH)
                .append(": ")
                .append(outOfScopeResponseBody.length())
                .append(crlf);

        HttpResponseHeader responseHeader;
        try {
            responseHeader = new HttpResponseHeader(strBuilder.toString());
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error("Failed to create a valid response header: ", e);
            responseHeader = new HttpResponseHeader();
        }
        outOfScopeResponseHeader = responseHeader;
    }

    public ClientSpider(
            ExtensionClientIntegration extClient,
            String displayName,
            String targetUrl,
            ClientOptions options,
            int id) {
        this(extClient, displayName, targetUrl, options, id, null, null, false, null);
    }

    @Override
    public void run() {
        startTime = System.currentTimeMillis();
        lastEventReceivedtime = startTime;
        if (options.getMaxDuration() > 0) {
            maxTime = startTime + TimeUnit.MINUTES.toMillis(options.getMaxDuration());
        }
        Stats.incCounter("stats.client.spider.started");
        if (user != null) {
            Stats.incCounter("stats.client.spider.started.user");
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
        ClientSideDetails details = node.getUserObject();
        String nodeUrl = details.getUrl();
        if (!node.isStorage()
                && !details.isVisited()
                && !details.isContentLoaded()
                && isUrlInScope(nodeUrl)) {
            urls.add(nodeUrl);
        }
        for (int i = 0; i < node.getChildCount(); i++) {
            getUnvisitedUrls(node.getChildAt(i), urls);
        }
    }

    public WebDriverProcess getWebDriverProcess() {
        WebDriverProcess wdp;
        synchronized (this.webDriverPool) {
            if (!this.webDriverPool.isEmpty()) {
                wdp = this.webDriverPool.remove(0);
            } else {
                try {
                    wdp =
                            new WebDriverProcess(
                                    extensionNetwork, extSelenium, new ProxyHandler(), options);
                } catch (IOException e) {
                    throw new RuntimeException("Failed to create WebDriver process:", e);
                }
            }
            this.webDriverActive.add(wdp);
        }
        return wdp;
    }

    public void returnWebDriverProcess(WebDriverProcess wdp) {
        // Deliberately synchronized on webDriverPool as they are modified together
        synchronized (this.webDriverPool) {
            this.webDriverActive.remove(wdp);
            this.webDriverPool.add(wdp);
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
            LOGGER.debug("Failed to add task: {}", e.getMessage());
        }
        return null;
    }

    private synchronized void executeTask(ClientSpiderTask task) {
        this.spiderTasks.add(task);
        this.threadPool.execute(task);
    }

    protected synchronized void postTaskExecution(ClientSpiderTask task) {
        if (spiderTasks.remove(task)) {
            tasksDoneCount++;
        }
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
            Stats.incCounter("stats.client.spider.event.max.time");
            this.stopScan();
            return;
        }

        Map<String, String> parameters = event.getParameters();
        String url = parameters.get(ClientMap.URL_KEY);
        if (!isUrlInScope(url)) {
            Stats.incCounter("stats.client.spider.event.scope.out");
            return;
        }

        Stats.incCounter("stats.client.spider.event.scope.in");
        addUriToAddedNodesModel(url);

        if (options.getMaxDepth() > 0) {
            int depth = Integer.parseInt(parameters.get(ClientMap.DEPTH_KEY));
            if (depth > options.getMaxDepth()) {
                LOGGER.debug(
                        "Ignoring URL - too deep {} > {} : {}", depth, options.getMaxDepth(), url);
                Stats.incCounter("stats.client.spider.event.max.depth");
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
                Stats.incCounter("stats.client.spider.event.max.children");
                return;
            }
        }

        if (ClientMap.MAP_COMPONENT_ADDED_EVENT.equals(event.getEventType())) {
            Stats.incCounter("stats.client.spider.event.component");
            if (ClickElement.isSupported(this::isUrlInScope, parameters)) {
                Stats.incCounter("stats.client.spider.event.component.click");
                addTask(
                        url,
                        openAction(
                                url, new ClickElement(valueProvider, createUri(url), parameters)),
                        options.getPageLoadTimeInSecs(),
                        Constant.messages.getString("client.spider.panel.table.action.click"),
                        paramsToString(parameters));
            } else if (SubmitForm.isSupported(parameters)) {
                Stats.incCounter("stats.client.spider.event.component.form");
                addTask(
                        url,
                        openAction(url, new SubmitForm(valueProvider, createUri(url), parameters)),
                        options.getPageLoadTimeInSecs(),
                        Constant.messages.getString("client.spider.panel.table.action.submit"),
                        paramsToString(parameters));
            }
        } else {
            Stats.incCounter("stats.client.spider.event.url");
            addOpenUrlTask(url, options.getPageLoadTimeInSecs());
        }
    }

    private boolean isUrlInScope(String url) {
        URI uri = createUri(url);
        if (uri == null) {
            return false;
        }

        char[] host = uri.getRawHost();
        if (host == null) {
            return true;
        }

        return checkResourceState(uri, new String(uri.getRawHost()), false)
                == ResourceState.ALLOWED;
    }

    protected ResourceState checkResourceState(HttpMessage msg, boolean allowAll) {
        return checkResourceState(
                msg.getRequestHeader().getURI(), msg.getRequestHeader().getHostName(), allowAll);
    }

    protected ResourceState checkResourceState(URI uri, String hostName, boolean allowAll) {
        ResourceState state = ResourceState.ALLOWED;
        String uriString = uri.toString();
        if (httpPrefixUriValidator != null && !httpPrefixUriValidator.isValid(uri)) {
            LOGGER.debug("Excluding resource not under subtree: {}", uriString);
            state = ResourceState.OUT_OF_SUBTREE;
        } else if (context != null) {
            if (!context.isInContext(uriString)) {
                LOGGER.debug("Excluding resource not in specified context: {}", uriString);
                state = ResourceState.OUT_OF_CONTEXT;
            }
        } else if (!targetHost.equalsIgnoreCase(hostName)) {
            LOGGER.debug("Excluding resource not on target host: {}", uriString);
            state = ResourceState.OUT_OF_HOST;
        }
        if (state == ResourceState.ALLOWED) {
            for (String regex : exclusionList) {
                if (Pattern.matches(regex, uriString)) {
                    LOGGER.debug("Excluding resource with {} {}", regex, uriString);
                    state = ResourceState.EXCLUDED;
                }
            }
        }
        if (state != ResourceState.ALLOWED && allowAll) {
            state = ResourceState.THIRD_PARTY;
        }

        return state;
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

    private static URI createUri(String value) {
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

    void taskStateChange(final ClientSpiderTask task) {
        tasksModel.updateTaskState(task.getId(), task.getStatus().toString(), task.getError());
    }

    private void addTaskToTasksModel(final ClientSpiderTask task, String url) {
        tasksModel.addTask(
                task.getId(),
                task.getDisplayName(),
                url,
                task.getDetailsString(),
                task.getStatus().toString());
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

        threadPool.shutdown();
        try {
            if (!threadPool.awaitTermination(
                    Math.max(1, options.getPageLoadTimeInSecs()) * 2, TimeUnit.SECONDS)) {
                LOGGER.warn("Failed to await for all tasks to stop in the expected time.");
                for (Runnable task : this.threadPool.shutdownNow()) {
                    ((ClientSpiderTask) task).cleanup();
                }
            }
        } catch (InterruptedException ignore) {
            Thread.currentThread().interrupt();
            LOGGER.warn("Interrupted while awaiting for all tasks to stop.");
        }

        synchronized (this.webDriverPool) {
            clear(webDriverPool);
            clear(webDriverActive);
        }

        int contentLoaded = 0;
        for (String url : crawledUrls) {
            if (extClient.setContentLoaded(url)) {
                contentLoaded++;
            }
        }

        if (listener != null) {
            listener.scanFinshed(scanId, displayName);
        }

        Stats.incCounter("stats.client.spider.time", timeTaken);
        Stats.incCounter("stats.client.spider.urls", crawledUrls.size());
        Stats.incCounter(
                "stats.client.spider.nodes", addedNodesModel.getRowCount() + contentLoaded);
        Stats.incCounter("stats.client.spider.nodes.found", addedNodesModel.getRowCount());
        Stats.incCounter("stats.client.spider.nodes.contentLoaded", contentLoaded);
    }

    private static void clear(Collection<WebDriverProcess> entries) {
        entries.forEach(WebDriverProcess::shutdown);
        entries.clear();
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

    public TableModel getMessagesTableModel() {
        return messagesTableModel;
    }

    public int getCountCrawledUrls() {
        return crawledUrls.size();
    }

    public void setListener(ScanListenner2 listener) {
        this.listener = listener;
    }

    void unload() {
        messagesTableModel.unload();
    }

    @Getter
    static class WebDriverProcess {

        private static final String LOCAL_PROXY_IP = "127.0.0.1";
        private static final int INITIATOR = HttpSender.CLIENT_SPIDER_INITIATOR;

        private Server proxy;
        private WebDriver webDriver;

        private WebDriverProcess(
                ExtensionNetwork extensionNetwork,
                ExtensionSelenium extensionSelenium,
                ProxyHandler proxyHandler,
                ClientOptions options)
                throws IOException {
            proxy =
                    extensionNetwork.createHttpServer(
                            HttpServerConfig.builder()
                                    .setHttpMessageHandler(proxyHandler)
                                    .setHttpSender(new HttpSender(INITIATOR))
                                    .setServeZapApi(true)
                                    .build());
            int port = proxy.start(Server.ANY_PORT);

            webDriver =
                    extensionSelenium.getWebDriver(
                            INITIATOR, options.getBrowserId(), LOCAL_PROXY_IP, port);
            if (ScopeCheck.STRICT.equals(options.getScopeCheck())) {
                proxyHandler.setAllowAll(false);
            }
        }

        private void shutdown() {
            if (webDriver != null) {
                try {
                    webDriver.quit();
                } catch (Exception e) {
                    LOGGER.debug("An error occurred while quitting the browser.", e);
                }
            }

            if (proxy != null) {
                try {
                    proxy.close();
                } catch (IOException e) {
                    LOGGER.debug("An error occurred while stopping the proxy.", e);
                }
            }
        }
    }

    private class ProxyHandler implements HttpMessageHandler {

        private boolean allowAll = true;

        public void setAllowAll(boolean allowAll) {
            this.allowAll = allowAll;
        }

        @Override
        public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage httpMessage) {
            if (!ctx.isFromClient()) {
                notifyMessage(
                        httpMessage,
                        HistoryReference.TYPE_CLIENT_SPIDER,
                        getResourceState(httpMessage));
                return;
            }

            ResourceState state = ResourceState.ALLOWED;
            if (isAllowedResource(httpMessage.getRequestHeader().getURI())) {
                // Nothing to do, state already set to allowed.
            } else {
                state = checkResourceState(httpMessage, allowAll);
            }

            if (state != ResourceState.ALLOWED && state != ResourceState.THIRD_PARTY) {
                setOutOfScopeResponse(httpMessage);
                notifyMessage(httpMessage, HistoryReference.TYPE_CLIENT_SPIDER_TEMPORARY, state);
                ctx.overridden();
                return;
            }

            if (extClient.getAuthenticationHandlers().isEmpty()) {
                httpMessage.setRequestingUser(user);
            }
        }

        private boolean isAllowedResource(URI uri) {
            String uriString = uri.toString();
            return allowedResources.stream().anyMatch(e -> e.matcher(uriString).matches());
        }

        private ResourceState getResourceState(HttpMessage httpMessage) {
            if (!httpMessage.isResponseFromTargetHost()) {
                return ResourceState.IO_ERROR;
            }
            return checkResourceState(httpMessage, allowAll);
        }

        private void setOutOfScopeResponse(HttpMessage httpMessage) {
            try {
                httpMessage.setTimeSentMillis(System.currentTimeMillis());
                httpMessage.setTimeElapsedMillis(0);
                httpMessage.setResponseHeader(outOfScopeResponseHeader.toString());
            } catch (HttpMalformedHeaderException ignore) {
                // Setting a valid response header.
            }
            httpMessage.setResponseBody(outOfScopeResponseBody.getBytes());
        }

        private void notifyMessage(HttpMessage httpMessage, int historyType, ResourceState state) {
            try {
                HistoryReference historyRef =
                        new HistoryReference(session, historyType, httpMessage);
                ThreadUtils.invokeLater(
                        () -> {
                            if (state == ResourceState.ALLOWED
                                    || state == ResourceState.THIRD_PARTY) {
                                crawledUrl(httpMessage.getRequestHeader().getURI().toString());
                                session.getSiteTree().addPath(historyRef, httpMessage);
                            }

                            messagesTableModel.addHistoryReference(historyRef, state);
                        });
            } catch (HttpMalformedHeaderException | DatabaseException e) {
                LOGGER.error(e, e);
            }
        }
    }

    private void crawledUrl(String url) {
        if (crawledUrls.add(url)) {
            extClient.updateAddedCount();
        }
    }
}
