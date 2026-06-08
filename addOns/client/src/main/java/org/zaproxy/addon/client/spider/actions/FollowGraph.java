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
package org.zaproxy.addon.client.spider.actions;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.BooleanSupplier;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jgrapht.Graph;
import org.jgrapht.GraphPath;
import org.jgrapht.alg.shortestpath.BFSShortestPath;
import org.jgrapht.graph.DefaultEdge;
import org.openqa.selenium.WebDriver;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.graph.ClientGraphVertex;
import org.zaproxy.addon.client.spider.SpiderAction;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.zap.utils.Stats;

public class FollowGraph implements SpiderAction {

    private static final Logger LOGGER = LogManager.getLogger(FollowGraph.class);

    private static final String STATS_PREFIX = "stats.client.spider.action.follow";

    private final Graph<ClientGraphVertex, DefaultEdge> graph;
    private final String targetUrl;
    private final ValueProvider valueProvider;
    private final BooleanSupplier waitAction;

    public FollowGraph(
            Graph<ClientGraphVertex, DefaultEdge> graph,
            String targetUrl,
            ValueProvider valueProvider,
            Duration waitDuration) {
        this.graph = Objects.requireNonNull(graph);
        this.targetUrl = Objects.requireNonNull(targetUrl);
        this.valueProvider = Objects.requireNonNull(valueProvider);
        waitAction = createWaitAction(waitDuration.toMillis());
    }

    private static BooleanSupplier createWaitAction(long millis) {
        if (millis <= 0) {
            return () -> false;
        }
        return new WaitAction(millis);
    }

    @Override
    public boolean run(WebDriver wd) {
        Stats.incCounter(STATS_PREFIX);

        String currentUrl = wd.getCurrentUrl();
        if (targetUrl.equals(currentUrl)) {
            Stats.incCounter(STATS_PREFIX + ".current");
            return true;
        }

        if (followPath(wd, currentUrl, targetUrl)) {
            Stats.incCounter(STATS_PREFIX + ".path");
            return true;
        }

        Stats.incCounter(STATS_PREFIX + ".fallback");
        LOGGER.debug("No graph path to {}, falling back to direct navigation", targetUrl);
        wd.get(targetUrl);
        return true;
    }

    private boolean followPath(WebDriver wd, String fromUrl, String toUrl) {
        ClientGraphVertex source = new ClientGraphVertex.Url(fromUrl);
        ClientGraphVertex target = new ClientGraphVertex.Url(toUrl);

        GraphPath<ClientGraphVertex, DefaultEdge> path;
        synchronized (graph) {
            if (!graph.containsVertex(source) || !graph.containsVertex(target)) {
                return false;
            }
            path = BFSShortestPath.findPathBetween(graph, source, target);
        }

        if (path == null) {
            return false;
        }

        List<ClientGraphVertex> vertices = path.getVertexList();
        for (ClientGraphVertex vertex : vertices) {
            if (vertex instanceof ClientGraphVertex.Component componentVertex) {
                if (waitAction.getAsBoolean()) {
                    return false;
                }

                ClientSideComponent component = componentVertex.component();
                try {
                    URI uri = new URI(component.getParentUrl(), true);
                    if (!new FollowClickElement(valueProvider, uri, component.getData()).run(wd)) {
                        return false;
                    }
                } catch (URIException e) {
                    LOGGER.debug("Failed to create URI for component click", e);
                    return false;
                }
            }
        }
        return true;
    }

    private static class FollowClickElement extends ClickElement {

        private static final String STATS_PREFIX = FollowGraph.STATS_PREFIX + ".click";

        private final String tagName;

        public FollowClickElement(
                ValueProvider valueProvider, URI uri, Map<String, String> elementData) {
            super(valueProvider, uri, elementData, true);
            tagName = getTagName(elementData);
        }

        @Override
        protected String getStatsPrefix() {
            return STATS_PREFIX + ".tag." + tagName;
        }
    }

    private static class WaitAction implements BooleanSupplier {

        private final long millis;
        private boolean first;

        WaitAction(long millis) {
            this.millis = millis;
            first = true;
        }

        @Override
        public boolean getAsBoolean() {
            if (first) {
                first = false;
                return false;
            }

            try {
                Thread.sleep(millis);
                return false;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return true;
        }
    }
}
