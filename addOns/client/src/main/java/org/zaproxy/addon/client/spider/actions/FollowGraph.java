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
import org.zaproxy.addon.client.internal.InteractableState;
import org.zaproxy.addon.client.internal.graph.ClientGraphVertex;
import org.zaproxy.addon.client.spider.SpiderAction;
import org.zaproxy.addon.client.spider.TaskContext;
import org.zaproxy.zap.utils.Stats;

public class FollowGraph implements SpiderAction {

    private static final Logger LOGGER = LogManager.getLogger(FollowGraph.class);

    private static final String STATS_PREFIX = "stats.client.spider.action.follow";

    private final ClientGraphVertex target;

    public FollowGraph(String targetUrl) {
        this.target = new ClientGraphVertex.Url(Objects.requireNonNull(targetUrl));
    }

    public FollowGraph(ClientGraphVertex.Component targetComponent) {
        this.target = Objects.requireNonNull(targetComponent);
    }

    @Override
    public boolean run(TaskContext context) {
        Stats.incCounter(STATS_PREFIX);

        String currentUrl = context.getWebDriver().getCurrentUrl();

        if (target instanceof ClientGraphVertex.Url urlTarget) {
            String url = urlTarget.url();
            if (url.equals(currentUrl) || url.equals(currentUrl + "#")) {
                Stats.incCounter(STATS_PREFIX + ".current");
                return true;
            }
        }

        if (followPath(context, currentUrl)) {
            Stats.incCounter(STATS_PREFIX + ".path");
            return true;
        }

        if (context.isStopped()) {
            return false;
        }

        if (target instanceof ClientGraphVertex.Url urlTarget) {
            Stats.incCounter(STATS_PREFIX + ".fallback");
            LOGGER.debug("No graph path to {}, falling back to direct navigation", urlTarget.url());
            context.getWebDriver().get(urlTarget.url());
            return context.getWaitStrategy().waitAfterPageLoad(urlTarget.url());
        }

        Stats.incCounter(STATS_PREFIX + ".fallback.nopath");
        LOGGER.debug("No graph path to target component state");
        return false;
    }

    private boolean followPath(TaskContext context, String fromUrl) {
        ClientGraphVertex source = new ClientGraphVertex.Url(fromUrl);

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
            if (context.isStopped()) {
                return false;
            }
            if (!(vertex instanceof ClientGraphVertex.Component componentVertex)) {
                continue;
            }

            ClientSideComponent comp = componentVertex.component();
            InteractableState state = componentVertex.state();
            InteractableState currentState = comp.getInteractable();

            if (state != null) {
                if (!state.equals(currentState)) {
                    LOGGER.debug("Component {} not in wanted state, aborting path", comp.getId());
                    Stats.incCounter(STATS_PREFIX + ".skip.statemismatch");
                    return false;
                }
            } else if (currentState != null
                    && !(currentState.isVisible() && currentState.isEnabled())) {
                LOGGER.debug("Component {} not interactable, aborting path", comp.getId());
                Stats.incCounter(STATS_PREFIX + ".skip.noninteractable");
                return false;
            }

            if (vertex.equals(target)) {
                return !context.isStopped();
            }

            try {
                URI uri = new URI(comp.getParentUrl(), true);
                if (!new FollowClickElement(uri, comp).run(context)) {
                    return false;
                }
            } catch (URIException e) {
                LOGGER.debug("Failed to create URI for intermediate component click", e);
                return false;
            }
        }

        if (target instanceof ClientGraphVertex.Url urlTarget) {
            return !context.isStopped()
                    && context.getWaitStrategy().waitAfterPageLoad(urlTarget.url());
        }
        return false;
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
