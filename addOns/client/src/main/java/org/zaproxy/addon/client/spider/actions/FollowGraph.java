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

import java.util.List;
import java.util.Objects;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.jgrapht.GraphPath;
import org.jgrapht.alg.shortestpath.BFSShortestPath;
import org.jgrapht.graph.DefaultEdge;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.graph.ClientGraphVertex;
import org.zaproxy.addon.client.spider.SpiderAction;
import org.zaproxy.addon.client.spider.TaskContext;
import org.zaproxy.zap.utils.Stats;

public class FollowGraph implements SpiderAction {

    private static final Logger LOGGER = LogManager.getLogger(FollowGraph.class);

    private static final String STATS_PREFIX = "stats.client.spider.action.follow";

    private final String targetUrl;

    public FollowGraph(String targetUrl) {
        this.targetUrl = Objects.requireNonNull(targetUrl);
    }

    @Override
    public boolean run(TaskContext context) {
        Stats.incCounter(STATS_PREFIX);

        String currentUrl = context.getWebDriver().getCurrentUrl();
        if (targetUrl.equals(currentUrl) || targetUrl.equals(currentUrl + "#")) {
            Stats.incCounter(STATS_PREFIX + ".current");
            return true;
        }

        if (followPath(context, currentUrl, targetUrl)) {
            Stats.incCounter(STATS_PREFIX + ".path");
            return true;
        }

        Stats.incCounter(STATS_PREFIX + ".fallback");
        LOGGER.debug("No graph path to {}, falling back to direct navigation", targetUrl);
        context.getWebDriver().get(targetUrl);
        return context.getWaitStrategy().waitAfterPageLoad(targetUrl);
    }

    private boolean followPath(TaskContext context, String fromUrl, String toUrl) {
        ClientGraphVertex source = new ClientGraphVertex.Url(fromUrl);
        ClientGraphVertex target = new ClientGraphVertex.Url(toUrl);

        GraphPath<ClientGraphVertex, DefaultEdge> path;
        synchronized (context.getGraph()) {
            if (!context.getGraph().containsVertex(source)
                    || !context.getGraph().containsVertex(target)) {
                return false;
            }
            path = BFSShortestPath.findPathBetween(context.getGraph(), source, target);
        }

        if (path == null) {
            return false;
        }

        List<ClientGraphVertex> vertices = path.getVertexList();
        for (ClientGraphVertex vertex : vertices) {
            if (vertex instanceof ClientGraphVertex.Component componentVertex) {
                ClientSideComponent component = componentVertex.component();
                try {
                    URI uri = new URI(component.getParentUrl(), true);
                    if (!new FollowClickElement(uri, component).run(context)) {
                        return false;
                    }
                } catch (URIException e) {
                    LOGGER.debug("Failed to create URI for component click", e);
                    return false;
                }
            }
        }
        return context.getWaitStrategy().waitAfterPageLoad(toUrl);
    }

    private static class FollowClickElement extends ClickElement {

        private static final String STATS_PREFIX = FollowGraph.STATS_PREFIX + ".click";

        public FollowClickElement(URI uri, ClientSideComponent component) {
            super(uri, component, true);
        }

        @Override
        protected String getStatsPrefix() {
            return STATS_PREFIX + ".tag." + component.getTagName();
        }
    }
}
