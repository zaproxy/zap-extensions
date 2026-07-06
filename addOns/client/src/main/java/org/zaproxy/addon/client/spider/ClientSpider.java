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
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import javax.swing.table.TableModel;
import lombok.Getter;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jgrapht.Graph;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.DirectedMultigraph;
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
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.client.ExtensionClientIntegration;
import org.zaproxy.addon.client.internal.ClientMap;
import org.zaproxy.addon.client.internal.ClientMapListener;
import org.zaproxy.addon.client.internal.ClientNode;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.ClientSideDetails;
import org.zaproxy.addon.client.internal.InteractableState;
import org.zaproxy.addon.client.internal.graph.ClientGraphVertex;
import org.zaproxy.addon.client.spider.ClientSpiderOptions.ScopeCheck;
import org.zaproxy.addon.client.spider.actions.ClickElement;
import org.zaproxy.addon.client.spider.actions.FollowGraph;
import org.zaproxy.addon.client.spider.actions.SubmitForm;
import org.zaproxy.addon.commonlib.AuthConstants;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.addon.network.server.HttpServerConfig;
import org.zaproxy.addon.network.server.Server;
import org.zaproxy.zap.extension.selenium.DriverConfiguration;
import org.zaproxy.zap.extension.selenium.DriverConfiguration.DriverConfigurationBuilder;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.GenericScanner2;
import org.zaproxy.zap.model.ScanListenner2;
import org.zaproxy.zap.network.HttpResponseBody;
import org.zaproxy.zap.users.User;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.ThreadUtils;

public class ClientSpider implements GenericScanner2 {

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
    private ClientSpiderOptions options;
    private int scanId;
    private String displayName;

    private String targetUrl;
    private final String targetHost;
    private final HttpPrefixUriValidator httpPrefixUriValidator;
    private final ScanOptions scanOptions;
    private ExtensionClientIntegration extClient;
    private final ClientMap clientMap;
    private final ExtensionSelenium extSelenium;
    private final ExtensionNetwork extensionNetwork;

    private final Session session;
    private final List<String> exclusionList;

    private List<WebDriverProcess> webDriverPool = new ArrayList<>();
    private Set<WebDriverProcess> webDriverActive = new HashSet<>();
    private Set<Integer> proxyPorts = ConcurrentHashMap.newKeySet();
    private final Map<Integer, TaskContext> contextByPort = new ConcurrentHashMap<>();
    private Set<String> visitedUrls = ConcurrentHashMap.newKeySet();
    private Set<String> discoveredUrls = Collections.synchronizedSet(new LinkedHashSet<>());
    private ClientMapListener clientMapListener;
    private List<ClientSpiderTask> spiderTasks = new ArrayList<>();
    private List<ClientSpiderTask> pausedTasks = new ArrayList<>();
    private long startTime;
    private long lastEventReceivedtime;
    private long maxTime;
    private boolean paused;
    private final AtomicBoolean stopping = new AtomicBoolean(false);
    private volatile boolean finished;
    private boolean stopped;

    private int tasksDoneCount;
    private final AtomicInteger tasksTotalCount;

    private UrlTableModel addedNodesModel;
    private TaskTableModel tasksModel;
    private final MessagesTableModel messagesTableModel;
    private final Set<String> crawledUrls;
    private final Graph<ClientGraphVertex, DefaultEdge> crawledGraph =
            new DirectedMultigraph<>(DefaultEdge.class);
    private ScanListenner2 listener;
    private final Control.Mode mode;

    public ClientSpider(
            ExtensionClientIntegration extClient,
            ClientMap clientMap,
            String displayName,
            String targetUrl,
            ClientSpiderOptions options,
            int id,
            Context context,
            User user,
            boolean subtreeOnly,
            ValueProvider valueProvider) {
        this(
                extClient,
                clientMap,
                displayName,
                targetUrl,
                options,
                ScanOptions.builder()
                        .setContext(context)
                        .setUser(user)
                        .setSubtreeOnly(subtreeOnly)
                        .build(),
                valueProvider,
                id);
    }

    public ClientSpider(
            ExtensionClientIntegration extClient,
            ClientMap clientMap,
            String displayName,
            String targetUrl,
            ClientSpiderOptions options,
            ScanOptions scanOptions,
            ValueProvider valueProvider,
            int id) {
        this.extClient = extClient;
        this.clientMap = clientMap;
        session = extClient.getModel().getSession();
        this.displayName = displayName;
        this.targetUrl = targetUrl;
        URI targetUri = createUri(targetUrl);
        targetHost = new String(targetUri.getRawHost());
        this.options = options;
        this.scanId = id;
        this.tasksTotalCount = new AtomicInteger();
        this.valueProvider = valueProvider;
        this.scanOptions = scanOptions;
        this.addedNodesModel = new UrlTableModel();
        this.tasksModel = new TaskTableModel();
        this.mode = Control.getSingleton().getMode();

        messagesTableModel = new MessagesTableModel();
        crawledUrls = Collections.synchronizedSet(new TreeSet<>());

        clientMapListener = new ClientMapListenerImpl();
        clientMap.addListener(clientMapListener);

        extSelenium = getExtension(ExtensionSelenium.class);
        extensionNetwork = getExtension(ExtensionNetwork.class);

        exclusionList = new ArrayList<>();
        exclusionList.addAll(session.getExcludeFromSpiderRegexs());
        exclusionList.addAll(session.getGlobalExcludeURLRegexs());

        HttpPrefixUriValidator validator =
                scanOptions.isSubtreeOnly() ? new HttpPrefixUriValidator(targetUri) : null;
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

    @Override
    public void run() {
        startTime = System.currentTimeMillis();
        lastEventReceivedtime = startTime;
        if (options.getMaxDuration() > 0) {
            maxTime = startTime + TimeUnit.MINUTES.toMillis(options.getMaxDuration());
        }
        Stats.incCounter("stats.client.spider.started");
        if (scanOptions.getUser() != null) {
            Stats.incCounter("stats.client.spider.started.user");
            synchronized (this.extClient.getAuthenticationHandlers()) {
                this.extClient
                        .getAuthenticationHandlers()
                        .forEach(handler -> handler.enableAuthentication(scanOptions.getUser()));
            }
        }

        this.threadPool =
                Executors.newFixedThreadPool(
                        options.getThreadCount(),
                        new ClientSpiderThreadFactory(
                                scanOptions.getThreadPrefix() + scanId + "-thread-"));

        if (scanOptions.isExistingOnly()) {
            addExistingTasks(clientMap.getRoot());
            if (spiderTasks.isEmpty()) {
                finished();
                return;
            }
        } else {
            addTask(
                    targetUrl,
                    followGraphAction(targetUrl),
                    Constant.messages.getString("client.spider.panel.table.action.get"),
                    "");

            // Add all of the known but unvisited URLs otherwise these will get ignored
            getUnvisitedUrls().forEach(this::addFollowGraphTask);
        }
    }

    TaskContext createTaskContext() {
        WebDriverProcess wdp = getWebDriverProcess();
        TaskContext ctx = new TaskContext(this::isStopped, wdp, valueProvider, clientMap);
        contextByPort.put(wdp.getProxyPort(), ctx);
        return ctx;
    }

    private List<SpiderAction> followGraphAction(String url, SpiderAction... additionalActions) {
        List<SpiderAction> actions = new ArrayList<>(5);
        actions.add(new FollowGraph(url));
        actions.add(
                context -> {
                    checkRedirect(url, context.getWebDriver());
                    return true;
                });
        if (additionalActions != null) {
            Stream.of(additionalActions).forEach(actions::add);
        }
        return actions;
    }

    private ClientSpiderTask addFollowGraphTask(String url) {
        return addTask(
                url,
                followGraphAction(url),
                Constant.messages.getString("client.spider.panel.table.action.follow"),
                "");
    }

    private void checkRedirect(String url, WebDriver wd) {
        String actualUrl = wd.getCurrentUrl();
        if (!url.equals(actualUrl)) {
            setRedirect(url, actualUrl);
        }
    }

    private List<String> getUnvisitedUrls() {
        List<String> urls = new ArrayList<>();
        ClientNode targetNode = clientMap.getNode(targetUrl, false, false);
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

    private void addExistingTasks(ClientNode node) {
        if (!node.isRoot()) {
            ClientSideDetails details = node.getUserObject();
            String nodeUrl = details.getUrl();
            if (!node.isStorage()
                    && (details.isVisited() || details.isContentLoaded())
                    && isUrlInScope(nodeUrl)) {
                addFollowGraphTask(nodeUrl);
                for (ClientSideComponent component : details.getComponents()) {
                    if (SubmitForm.isSupported(component)) {
                        addSubmitTask(nodeUrl, component);
                    }
                }
            }
        }
        for (int i = 0; i < node.getChildCount(); i++) {
            addExistingTasks(node.getChildAt(i));
        }
    }

    private WebDriverProcess getWebDriverProcess() {
        WebDriverProcess wdp;
        synchronized (this.webDriverPool) {
            if (!this.webDriverPool.isEmpty()) {
                wdp = this.webDriverPool.remove(0);
            } else {
                try {
                    wdp = new WebDriverProcess();
                } catch (IOException e) {
                    throw new RuntimeException("Failed to create WebDriver process:", e);
                }
            }
            this.webDriverActive.add(wdp);
        }
        return wdp;
    }

    private void addSubmitTask(String nodeUrl, ClientSideComponent component) {
        addTask(
                nodeUrl,
                followGraphAction(nodeUrl, new SubmitForm(createUri(nodeUrl), component)),
                Constant.messages.getString("client.spider.panel.table.action.submit"),
                paramsToString(component));
    }

    private ClientSpiderTask addTask(
            String url, List<SpiderAction> actions, String displayName, String detailsString) {
        int id = tasksTotalCount.incrementAndGet();
        try {
            ClientSpiderTask task =
                    new ClientSpiderTask(id, this, actions, displayName, detailsString);
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

    protected synchronized void postTaskExecution(ClientSpiderTask task, TaskContext context) {
        if (context != null) {
            if (!scanOptions.isExistingOnly()) {
                processStateChangedComponents(context);
            }

            contextByPort.remove(context.getWebDriverProcess().getProxyPort());

            WebDriverProcess wdp = context.getWebDriverProcess();
            // Deliberately synchronized on webDriverPool as they are modified together
            synchronized (this.webDriverPool) {
                this.webDriverActive.remove(wdp);
                this.webDriverPool.add(wdp);
            }
        }

        if (spiderTasks.remove(task)) {
            tasksDoneCount++;
        }
        if (listener != null && !isExternalControl()) {
            listener.scanProgress(scanId, displayName, this.getProgress(), this.getMaximum());
        }
        if (isIdle()) {
            if (processDiscoveredUrls()) {
                return;
            }

            LOGGER.debug("No running tasks, starting shutdown timer");
            new ShutdownThread(options.getShutdownTimeInSecs()).start();
        }
    }

    private void processStateChangedComponents(TaskContext ctx) {
        List<ClientGraphVertex.Component> changed = ctx.getAndClearStateChangedComponents();
        if (changed.isEmpty()) {
            return;
        }
        ClientSideComponent lastActioned = ctx.getLastActionedComponent();
        ClientGraphVertex fromVertex =
                lastActioned != null ? new ClientGraphVertex.Component(lastActioned) : null;

        for (ClientGraphVertex.Component stateVertex : changed) {
            InteractableState state = stateVertex.state();
            if (state == null) {
                continue;
            }
            ClientSideComponent component = stateVertex.component();

            if (!markComponentStateAsHandled(stateVertex)) {
                continue;
            }

            String url = component.getParentUrl();
            if (!isUrlInScope(url)) {
                continue;
            }

            Stats.incCounter("stats.client.spider.event.component.statechanged");
            if (ClickElement.isSupported(ClientSpider.this::isUrlInScope, component)
                    && !(options.isLogoutAvoidance() && isLogoutElement(component))) {
                Stats.incCounter("stats.client.spider.event.component.statechanged.click");
                addCausalEdge(fromVertex, stateVertex, lastActioned);
                List<SpiderAction> actions = new ArrayList<>();
                actions.add(new FollowGraph(stateVertex));
                actions.add(new ClickElement(createUri(url), component, false));
                addTask(
                        url,
                        actions,
                        Constant.messages.getString("client.spider.panel.table.action.click"),
                        paramsToString(component));
            } else if (SubmitForm.isSupported(component)) {
                Stats.incCounter("stats.client.spider.event.component.statechanged.form");
                addCausalEdge(fromVertex, stateVertex, lastActioned);
                List<SpiderAction> actions = new ArrayList<>();
                actions.add(new FollowGraph(stateVertex));
                actions.add(new SubmitForm(createUri(url), component));
                addTask(
                        url,
                        actions,
                        Constant.messages.getString("client.spider.panel.table.action.submit"),
                        paramsToString(component));
            }
        }
    }

    private void addCausalEdge(
            ClientGraphVertex fromVertex,
            ClientGraphVertex.Component stateVertex,
            ClientSideComponent lastActioned) {
        synchronized (clientMap.getGraph()) {
            clientMap.getGraph().addVertex(stateVertex);
            if (fromVertex != null) {
                boolean added = clientMap.getGraph().addVertex(fromVertex);
                if (added) {
                    ClientGraphVertex parentUrl =
                            new ClientGraphVertex.Url(lastActioned.getParentUrl());
                    if (clientMap.getGraph().containsVertex(parentUrl)) {
                        clientMap.getGraph().addEdge(parentUrl, fromVertex);
                    }
                }
                clientMap.getGraph().addEdge(fromVertex, stateVertex);
            }
        }
    }

    private boolean markComponentStateAsHandled(ClientGraphVertex.Component vertex) {
        synchronized (crawledGraph) {
            if (crawledGraph.containsVertex(vertex)) {
                return false;
            }
            crawledGraph.addVertex(vertex);
            return true;
        }
    }

    private boolean isIdle() {
        return spiderTasks.isEmpty() && !paused && !stopping.get();
    }

    private boolean processDiscoveredUrls() {
        List<String> urlsToAdd = new ArrayList<>();

        synchronized (crawledUrls) {
            discoveredUrls.stream()
                    .filter(Predicate.not(crawledUrls::contains))
                    .forEach(urlsToAdd::add);
        }
        discoveredUrls.clear();

        for (String url : urlsToAdd) {
            addFollowGraphTask(url);
        }

        return !urlsToAdd.isEmpty();
    }

    private synchronized void addDiscoveredUrl(String url) {
        discoveredUrls.add(url);
        if (isIdle()) {
            processDiscoveredUrls();
        }
    }

    private class ClientMapListenerImpl implements ClientMapListener {

        private static final Pattern SCHEME_PATTERN =
                Pattern.compile("^https?://", Pattern.CASE_INSENSITIVE);

        private boolean shouldIgnore(String url, int source, int depth, int siblings) {
            if (stopping.get() || stopped || !proxyPorts.contains(source)) {
                return true;
            }

            lastEventReceivedtime = System.currentTimeMillis();
            if (maxTime > 0 && lastEventReceivedtime > maxTime) {
                LOGGER.debug("Exceeded max time, stopping");
                Stats.incCounter("stats.client.spider.event.max.time");
                stopScan();
                return true;
            }

            if (options.getMaxDepth() > 0) {
                if (depth > options.getMaxDepth()) {
                    LOGGER.debug(
                            "Ignoring URL - too deep {} > {} : {}",
                            depth,
                            options.getMaxDepth(),
                            url);
                    Stats.incCounter("stats.client.spider.event.max.depth");
                    return true;
                }
            }

            if (options.getMaxChildren() > 0) {
                if (siblings > options.getMaxChildren()) {
                    LOGGER.debug(
                            "Ignoring URL - too wide {} > {} : {}",
                            siblings,
                            options.getMaxChildren(),
                            url);
                    Stats.incCounter("stats.client.spider.event.max.children");
                    return true;
                }
            }

            if (!isUrlInScope(url)) {
                Stats.incCounter("stats.client.spider.event.scope.out");
                return true;
            }

            Stats.incCounter("stats.client.spider.event.scope.in");
            addUriToAddedNodesModel(url);
            return false;
        }

        @Override
        public void nodeAdded(String url, int depth, int siblings, int source) {
            if (scanOptions.isExistingOnly()) {
                return;
            }
            if (shouldIgnore(url, source, depth, siblings)) {
                return;
            }

            Stats.incCounter("stats.client.spider.event.url");
            addDiscoveredUrl(url);
        }

        private boolean isHrefAlreadyHandled(ClientSideComponent component) {
            String href = component.getHref();
            if (href == null || !SCHEME_PATTERN.matcher(href).find()) {
                return false;
            }

            String sourceUrl = component.getParentUrl();
            if (sourceUrl.equals(href)) {
                return true;
            }

            synchronized (crawledGraph) {
                ClientGraphVertex target = new ClientGraphVertex.Url(href);
                if (crawledGraph.containsVertex(target)) {
                    return true;
                }

                ClientGraphVertex source = new ClientGraphVertex.Url(sourceUrl);
                crawledGraph.addVertex(source);
                crawledGraph.addVertex(target);
                crawledGraph.addEdge(source, target);
                return false;
            }
        }

        @Override
        public void componentStateChanged(
                ClientSideComponent component, int depth, int siblings, int source) {
            if (stopping.get() || stopped || !proxyPorts.contains(source)) {
                return;
            }
            TaskContext ctx = contextByPort.get(source);
            if (ctx == null) {
                return;
            }
            ctx.addStateChangedComponent(component, component.getInteractable());
        }

        @Override
        public void componentAdded(
                ClientSideComponent component, int depth, int siblings, int source) {
            if (scanOptions.isExistingOnly()) {
                return;
            }
            String url = component.getParentUrl();
            if (shouldIgnore(url, source, depth, siblings)) {
                return;
            }

            InteractableState interactable = component.getInteractable();
            if (interactable != null && !(interactable.isEnabled() && interactable.isVisible())) {
                return;
            }

            Stats.incCounter("stats.client.spider.event.component");
            if (ClickElement.isSupported(ClientSpider.this::isUrlInScope, component)
                    && !(options.isLogoutAvoidance() && isLogoutElement(component))
                    && !isHrefAlreadyHandled(component)) {
                Stats.incCounter("stats.client.spider.event.component.click");
                addTask(
                        url,
                        followGraphAction(url, new ClickElement(createUri(url), component, false)),
                        Constant.messages.getString("client.spider.panel.table.action.click"),
                        paramsToString(component));
            } else if (SubmitForm.isSupported(component)) {
                Stats.incCounter("stats.client.spider.event.component.form");
                addSubmitTask(url, component);
            }
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
        } else if (scanOptions.getContext() != null) {
            if (!scanOptions.getContext().isInContext(uriString)) {
                LOGGER.debug("Excluding resource not in specified context: {}", uriString);
                state = ResourceState.OUT_OF_CONTEXT;
            }
        } else if (mode == Control.Mode.protect) {
            if (!session.isInScope(uriString)) {
                LOGGER.debug("Excluding resource not in scope in protected mode: {}", uriString);
                state = ResourceState.OUT_OF_HOST;
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
        if (state != ResourceState.ALLOWED && allowAll && mode != Control.Mode.protect) {
            state = ResourceState.THIRD_PARTY;
        }

        return state;
    }

    private static boolean isLogoutElement(ClientSideComponent component) {
        String text = component.getText();
        if (text == null || text.isBlank()) {
            return false;
        }
        String normalized = text.toLowerCase(Locale.ROOT).replaceAll("[ -]", "");
        return AuthConstants.getLogoutIndicators().stream().anyMatch(normalized::contains);
    }

    private static String paramsToString(ClientSideComponent component) {
        String tag = component.getTagName();
        if (tag != null) {
            switch (tag) {
                case "A":
                    return Constant.messages.getString(
                            "client.spider.panel.table.details.link",
                            component.getHref(),
                            component.getText());
                case "BUTTON":
                    return Constant.messages.getString(
                            "client.spider.panel.table.details.button", component.getText());
            }
        }
        return component.getData().toString();
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
        if (isExternalControl()) {
            return;
        }
        ThreadUtils.invokeLater(
                () -> {
                    addedNodesModel.addScanResult(uri);
                    extClient.updateAddedCount();
                });
    }

    void taskStateChange(final ClientSpiderTask task) {
        if (isExternalControl()) {
            return;
        }
        tasksModel.updateTaskState(task.getId(), task.getStatus().toString(), task.getError());
    }

    private void addTaskToTasksModel(final ClientSpiderTask task, String url) {
        if (isExternalControl()) {
            return;
        }
        tasksModel.addTask(
                task.getId(),
                task.getDisplayName(),
                url,
                task.getDetailsString(),
                task.getStatus().toString());
    }

    protected void setRedirect(String originalUrl, String redirectedUrl) {
        ThreadUtils.invokeLater(
                () -> {
                    clientMap.getOrAddNode(originalUrl, true, false);
                    clientMap.getOrAddNode(redirectedUrl, false, false);
                    clientMap.setRedirect(originalUrl, redirectedUrl);
                });
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
        new Thread(this::finished, "ZAP-ClientSpider-cleanup-" + scanId).start();
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

    public boolean isExternalControl() {
        return scanOptions.isExternalControl();
    }

    private void finished() {
        if (!stopping.compareAndSet(false, true)) {
            return;
        }
        long timeTaken = System.currentTimeMillis() - startTime;
        LOGGER.debug(
                "Spider finished {}", DurationFormatUtils.formatDuration(timeTaken, "HH:MM:SS"));
        if (scanOptions.getUser() != null) {
            synchronized (extClient.getAuthenticationHandlers()) {
                extClient
                        .getAuthenticationHandlers()
                        .forEach(handler -> handler.disableAuthentication(scanOptions.getUser()));
            }
        }

        threadPool.shutdown();
        try {
            if (!threadPool.awaitTermination(
                    Math.max(1, options.getShutdownTimeInSecs()) * 2, TimeUnit.SECONDS)) {
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

        clientMap.removeListener(clientMapListener);
        finished = true;

        int contentLoaded = 0;
        for (String url : crawledUrls) {
            if (clientMap.setContentLoaded(url) != null) {
                contentLoaded++;
            }
        }

        if (listener != null && !isExternalControl()) {
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
                    Thread.currentThread().interrupt();
                    break;
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
    public class WebDriverProcess {

        private static final String LOCAL_PROXY_IP = "127.0.0.1";

        private Server proxy;
        private WebDriver webDriver;
        private final int proxyPort;
        private final ActionWaitStrategy waitStrategy;
        private final ProxyHandler proxyHandler;

        private WebDriverProcess() throws IOException {
            this.waitStrategy = createWaitStrategy();
            this.proxyHandler = new ProxyHandler(waitStrategy);
            int initiator = scanOptions.getInitiator();
            HttpSender httpSender = scanOptions.getHttpSender();
            if (httpSender == null) {
                httpSender = new HttpSender(initiator);
            }
            proxy =
                    extensionNetwork.createHttpServer(
                            HttpServerConfig.builder()
                                    .setHttpMessageHandler(proxyHandler)
                                    .setHttpSender(httpSender)
                                    .setServeZapApi(true)
                                    .build());
            proxyPort = proxy.start(Server.ANY_PORT);
            proxyPorts.add(proxyPort);
            extClient.registerPortInitiator(proxyPort, initiator);

            clientMap.addListener(waitStrategy);

            DriverConfigurationBuilder driverConfBuilder =
                    DriverConfiguration.builder()
                            .requester(initiator)
                            .proxyAddress(LOCAL_PROXY_IP)
                            .proxyPort(proxyPort)
                            .enableExtensions(true);
            if (!scanOptions.getIncludeExtensions().isEmpty()) {
                driverConfBuilder.includeExtensions(scanOptions.getIncludeExtensions());
            }
            if (!scanOptions.getExcludeExtensions().isEmpty()) {
                driverConfBuilder.excludeExtensions(scanOptions.getExcludeExtensions());
            }

            try {
                webDriver =
                        extSelenium.getWebDriver(options.getBrowserId(), driverConfBuilder.build());
                if (ScopeCheck.STRICT.equals(options.getScopeCheck())
                        || mode == Control.Mode.protect) {
                    proxyHandler.setAllowAll(false);
                }
            } catch (Exception e) {
                closeProxy();
                throw e;
            }

            waitStrategy.configure(this);
        }

        private ActionWaitStrategy createWaitStrategy() {
            if (options.getPageLoadTimeInSecs() == 0 && options.getActionWaitTimeInSecs() == 0) {
                return new AdaptiveWaitStrategy(
                        options, ClientSpider.this::isUrlInScope, visitedUrls);
            }
            return new FixedWaitStrategy(
                    Duration.ofSeconds(options.getInitialLoadTimeInSecs()),
                    Duration.ofSeconds(options.getPageLoadTimeInSecs()),
                    Duration.ofSeconds(options.getActionWaitTimeInSecs()));
        }

        private void closeProxy() {
            if (proxy != null) {
                extClient.unregisterPortInitiator(proxyPort);
                clientMap.removeListener(waitStrategy);
                try {
                    proxy.close();
                } catch (IOException e) {
                    LOGGER.debug("An error occurred while stopping the proxy.", e);
                }
                proxy = null;
            }
        }

        private void shutdown() {
            if (webDriver != null) {
                try {
                    extClient.browserClosing(webDriver);
                    webDriver.quit();
                } catch (Exception e) {
                    LOGGER.warn("An error occurred while quitting the browser.", e);
                }
            }

            closeProxy();
        }
    }

    private class ProxyHandler implements HttpMessageHandler {

        private final ActionWaitStrategy waitStrategy;

        private boolean allowAll = true;

        ProxyHandler(ActionWaitStrategy waitStrategy) {
            this.waitStrategy = waitStrategy;
        }

        public void setAllowAll(boolean allowAll) {
            this.allowAll = allowAll;
        }

        @Override
        public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage httpMessage) {
            String uri = httpMessage.getRequestHeader().getURI().toString();
            if (ctx.isFromClient()) {
                waitStrategy.onRequestStarted(uri);
            } else {
                waitStrategy.onRequestCompleted(uri);
            }

            if (!ctx.isFromClient()) {
                handleRedirection(httpMessage);

                notifyMessage(
                        httpMessage, scanOptions.getHrefType(), getResourceState(httpMessage));
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
                notifyMessage(httpMessage, scanOptions.getTmpHrefType(), state);
                ctx.overridden();
                return;
            }

            if (extClient.getAuthenticationHandlers().isEmpty()) {
                httpMessage.setRequestingUser(scanOptions.getUser());
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
            if (isExternalControl()) {
                if (state == ResourceState.ALLOWED || state == ResourceState.THIRD_PARTY) {
                    crawledUrl(httpMessage.getRequestHeader().getURI().toString(), false);
                }
                return;
            }
            try {
                HistoryReference historyRef =
                        new HistoryReference(session, historyType, httpMessage);
                ThreadUtils.invokeLater(
                        () -> {
                            if (state == ResourceState.ALLOWED
                                    || state == ResourceState.THIRD_PARTY) {
                                crawledUrl(
                                        httpMessage.getRequestHeader().getURI().toString(), true);
                                historyRef.setCustomIcon(
                                        "org/zaproxy/addon/client/resources/spiderClient.png",
                                        true);
                                session.getSiteTree().addPath(historyRef, httpMessage);
                            }

                            messagesTableModel.addHistoryReference(historyRef, state);
                        });
            } catch (HttpMalformedHeaderException | DatabaseException e) {
                LOGGER.error(e, e);
            }
        }
    }

    private void handleRedirection(HttpMessage httpMessage) {
        if (!HttpStatusCode.isRedirection(httpMessage.getResponseHeader().getStatusCode())) {
            return;
        }

        String location = httpMessage.getResponseHeader().getHeader(HttpHeader.LOCATION);
        if (location == null || location.isBlank()) {
            return;
        }

        URI from = httpMessage.getRequestHeader().getURI();
        URI to = resolveUri(from, location.trim());

        if (to != null) {
            setRedirect(from.toString(), to.toString());
        }
    }

    private static URI resolveUri(URI base, String relative) {
        try {
            return new URI(base, relative, true);
        } catch (URIException ex) {
            try {
                return new URI(base, relative, false);
            } catch (URIException e) {
                LOGGER.debug("Unable to resolve {} with base {}", relative, base, e);
            }
        }
        return null;
    }

    private void crawledUrl(String url) {
        crawledUrl(url, !isExternalControl());
    }

    private void crawledUrl(String url, boolean updateUi) {
        if (crawledUrls.add(url) && updateUi) {
            extClient.updateAddedCount();
        }
    }
}
