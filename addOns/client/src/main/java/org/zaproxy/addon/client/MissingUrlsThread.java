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
package org.zaproxy.addon.client;

import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.model.StructuralNode;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.ThreadUtils;

public class MissingUrlsThread extends Thread {

    private static final Logger LOGGER = LogManager.getLogger(MissingUrlsThread.class);

    private HttpSender httpSender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);

    private Model model;
    private Event startEvent;
    private ClientNode rootNode;

    public MissingUrlsThread(Model model, Event event, ClientNode rootNode) {
        super("ZAP-Client-MissingUrls");
        this.model = model;
        this.startEvent = event;
        this.rootNode = rootNode;
    }

    @Override
    public void run() {
        Stats.incCounter("stats.client.ajax.scan");
        traverseMap(rootNode);
    }

    private void persistToHistoryAndSitesTree(HttpMessage msg) {
        HistoryReference historyRef;
        ExtensionHistory extHistory =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionHistory.class);
        try {
            historyRef =
                    new HistoryReference(
                            Model.getSingleton().getSession(), HistoryReference.TYPE_ZAP_USER, msg);
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
            return;
        }

        try {
            ThreadUtils.invokeAndWait(
                    () -> {
                        extHistory.addHistory(historyRef);
                        Model.getSingleton().getSession().getSiteTree().addPath(historyRef, msg);
                    });
        } catch (Exception e) {
            LOGGER.error("Could not add message to sites tree.", e);
        }
    }

    private void requestUrl(String url) {
        try {
            if (View.isInitialised()) {
                View.getSingleton()
                        .getOutputPanel()
                        .appendAsync(
                                Constant.messages.getString("client.output.requrl", url) + "\n");
            }
            HttpMessage msg = new HttpMessage(new URI(url, true));
            httpSender.sendAndReceive(msg);
            persistToHistoryAndSitesTree(msg);
            Stats.incCounter("stats.client.ajax.url.new");
        } catch (Exception e) {
            LOGGER.error(e, e);
        }
    }

    protected void traverseMap(ClientNode node) {
        ClientSideDetails csd = node.getUserObject();
        if (csd != null && !csd.isStorage() && csd.getUrl() != null) {
            String url = ClientUtils.stripUrlFragment(csd.getUrl());
            Target target = startEvent.getTarget();
            String startUrl = null;
            if (target != null && target.getStartNode() != null) {
                startUrl = target.getStartNode().toString();
            } else {
                startUrl = startEvent.getParameters().get("url");
            }
            if (startUrl == null && (target == null || target.getContext() == null)) {
                LOGGER.debug("Unable to determine start node");
            } else if (startUrl != null && !url.startsWith(startUrl)) {
                LOGGER.debug("URL not under startNode {}", url);
            } else if (target != null
                    && target.getContext() != null
                    && !target.getContext().isInContext(url)) {
                LOGGER.debug("URL not in context {}", url);
            } else if (!csd.isVisited() && !csd.isStorage()) {
                try {
                    StructuralNode siteNode =
                            SessionStructure.find(
                                    model, new URI(url, true), HttpRequestHeader.GET, "");
                    if (siteNode == null) {
                        // Found one not in the sites tree!
                        requestUrl(url);
                    }
                } catch (Exception e) {
                    LOGGER.error(e, e);
                }
            }
        }
        if (node.getChildCount() > 0) {
            node.children().asIterator().forEachRemaining(n -> traverseMap((ClientNode) n));
        }
    }

    /** Only for use in testing */
    protected void setHttpSender(HttpSender httpSender) {
        this.httpSender = httpSender;
    }
}
