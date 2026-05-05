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
package org.zaproxy.addon.client.internal;

import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeNode;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.client.ClientUtils;
import org.zaproxy.zap.ZAP;
import org.zaproxy.zap.eventBus.Event;
import org.zaproxy.zap.eventBus.EventPublisher;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.model.Target;
import org.zaproxy.zap.utils.ThreadUtils;

@SuppressWarnings("serial")
public class ClientMap extends SortedTreeModel implements EventPublisher {

    public static final String MAP_NODE_ADDED_EVENT = "client.mapNode.added";
    public static final String MAP_COMPONENT_ADDED_EVENT = "client.mapComponent.added";
    public static final String DEPTH_KEY = "depth";
    public static final String SIBLINGS_KEY = "siblings";
    public static final String URL_KEY = "url";
    public static final String MESSAGE_UUID_KEY = "client.message.uuid";

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LogManager.getLogger(ClientMap.class);
    private ClientNode root;
    private Consumer<ReportedObject> reportedObjectConsumer;

    public ClientMap(ClientNode root) {
        super(root);
        this.root = root;
        ZAP.getEventBus().registerPublisher(this, MAP_NODE_ADDED_EVENT, MAP_COMPONENT_ADDED_EVENT);
    }

    @Override
    public ClientNode getRoot() {
        return root;
    }

    public ClientNode getOrAddNode(String url, boolean visited, boolean storage) {
        LOGGER.debug("getOrAddNode {}", url);
        return this.getNode(url, visited, storage, true, true);
    }

    public ClientNode getNode(String url, boolean visited, boolean storage) {
        LOGGER.debug("getNode {}", url);
        return this.getNode(url, visited, storage, false, false);
    }

    private synchronized ClientNode getNode(
            String url, boolean visited, boolean storage, boolean add, boolean publishEvent) {
        if (url == null) {
            throw new IllegalArgumentException("The url parameter should not be null");
        }
        List<String> nodeNames =
                ClientUtils.urlToNodes(url, root.getSession().getUrlParamParser(url));

        ClientNode parent = root;
        ClientNode child = null;

        for (int i = 0; i < nodeNames.size(); i++) {
            String nodeName = nodeNames.get(i);
            boolean lastComponent = i == nodeNames.size() - 1;
            child = parent.getChild(nodeName, lastComponent && storage);
            if (child == null) {
                if (!add) {
                    return null;
                }
                if (lastComponent) {
                    child =
                            new ClientNode(
                                    new ClientSideDetails(nodeName, url, visited, storage),
                                    storage);
                    if (!storage && publishEvent) {
                        Map<String, String> map = new HashMap<>();
                        map.put(URL_KEY, url);
                        // Note we haven't added the child to the parent yet
                        map.put(DEPTH_KEY, Integer.toString(parent.getLevel() + 1));
                        map.put(SIBLINGS_KEY, Integer.toString(parent.getChildCount() + 1));
                        ZAP.getEventBus()
                                .publishSyncEvent(
                                        this,
                                        new Event(this, MAP_NODE_ADDED_EVENT, new Target(), map));
                    }
                } else {
                    // Create intermediate node with a suitable URL
                    String nodeUrl;
                    if (parent.isRoot()) {
                        nodeUrl = nodeName + "/";
                    } else {
                        boolean lastBeforeFragment =
                                (i <= nodeNames.size() - 2)
                                        && (nodeNames.get(i + 1).startsWith("#")
                                                || nodeNames.get(i + 1).startsWith("/#"));

                        if (lastBeforeFragment) {
                            // Special case - we will not have the param values at this point
                            nodeUrl = url.substring(0, url.indexOf("#"));
                        } else {
                            String pUrl = parent.getUserObject().getUrl();

                            if (nodeName.equals("#") || nodeName.equals("/#")) {
                                nodeUrl = pUrl + "#";
                            } else {
                                if (!pUrl.endsWith("/") && !nodeName.startsWith("/")) {
                                    pUrl += "/";
                                }
                                nodeUrl = pUrl + nodeName + "/";
                            }
                        }
                    }
                    child =
                            new ClientNode(
                                    new ClientSideDetails(nodeName, nodeUrl, false, false), false);
                }
                this.insertNodeInto(child, parent);
                this.nodeStructureChanged(parent);
            }
            parent = child;
        }
        return child;
    }

    public void deleteNodes(List<ClientNode> nodes) {
        for (ClientNode node : nodes) {
            if (!node.isRoot()) {
                removeNodeFromParent(node);
            }
        }
    }

    public void clear() {
        root.removeAllChildren();
        this.nodeStructureChanged(root);
    }

    @Override
    public String getPublisherName() {
        return this.getClass().getCanonicalName();
    }

    private void notifyNodeChanged(ClientNode node) {
        if (!View.isInitialised()) {
            return;
        }
        ThreadUtils.invokeAndWaitHandled(() -> nodeChanged(node));
    }

    public void addComponent(String url, ClientSideComponent component) {
        ClientNode node = getOrAddNode(url, false, false);
        addComponentToNode(node, component);
        if (component.isStorageEvent()) {
            String storageUrl = node.getSite() + component.getTypeForDisplay();
            addComponentToNode(getOrAddNode(storageUrl, false, true), component);
        }
    }

    public boolean addComponentToNode(ClientNode node, ClientSideComponent component) {
        ClientSideDetails details = node.getUserObject();
        boolean wasVisited = details.isVisited();
        boolean componentAdded = details.addComponent(component);
        if (!wasVisited || componentAdded) {
            details.setVisited(true);

            Map<String, String> map = new HashMap<>(component.getData());
            map.put(DEPTH_KEY, Integer.toString(node.getLevel()));
            map.put(SIBLINGS_KEY, Integer.toString(node.getChildCount()));
            ZAP.getEventBus()
                    .publishSyncEvent(
                            this, new Event(this, MAP_COMPONENT_ADDED_EVENT, new Target(), map));
            notifyNodeChanged(node);
        }
        return componentAdded;
    }

    public ClientNode setRedirect(String originalUrl, String redirectedUrl) {
        ClientNode node = getNode(originalUrl, false, false);
        if (node != null) {
            node.getUserObject().setRedirect(true);
            node.getUserObject().setVisited(true);
            node.getUserObject()
                    .addComponent(
                            new ClientSideComponent(
                                    Map.of(),
                                    ClientSideComponent.REDIRECT,
                                    null,
                                    originalUrl,
                                    redirectedUrl,
                                    ClientSideComponent.REDIRECT,
                                    ClientSideComponent.Type.REDIRECT,
                                    null,
                                    -1));
            notifyNodeChanged(node);
            return node;
        }
        LOGGER.debug("setRedirect, no node for URL {}", originalUrl);
        return null;
    }

    public ClientNode setVisited(String url) {
        ClientNode node = getNode(url, false, false);
        if (node != null && !node.getUserObject().isVisited()) {
            node.getUserObject().setVisited(true);
            notifyNodeChanged(node);
            return node;
        }
        LOGGER.debug("setVisited, no node for URL or already visited {}", url);
        return null;
    }

    public ClientNode setContentLoaded(String url) {
        ClientNode node = getNode(url, false, false, true, false);
        if (node.getUserObject().isVisited()) {
            return null;
        }

        node.getUserObject().setContentLoaded(true);
        node.getUserObject()
                .addComponent(
                        new ClientSideComponent(
                                Map.of(),
                                ClientSideComponent.CONTENT_LOADED,
                                null,
                                null,
                                null,
                                ClientSideComponent.CONTENT_LOADED,
                                ClientSideComponent.Type.CONTENT_LOADED,
                                null,
                                -1));
        notifyNodeChanged(node);
        return node;
    }

    public void setReportedObjectConsumer(Consumer<ReportedObject> consumer) {
        this.reportedObjectConsumer = consumer;
    }

    public void handleReportObject(String jsonStr) {
        handleReportObject(jsonStr, 0);
    }

    public void handleReportObject(String jsonStr, int source) {
        LOGGER.debug("Got object: {}", jsonStr);
        JSONObject json = JSONObject.fromObject(jsonStr);
        ReportedElement rnode = new ReportedElement(json);
        notifyReportedObjectConsumer(rnode);
        String url = rnode.getUrl();
        if (url != null) {
            if (!isApiUrl(url)) {
                addComponent(url, new ClientSideComponent(json));
            }
        } else {
            LOGGER.debug("Not got url:(: {}", url);
        }
        String href = rnode.getHref();
        if (href != null && href.toLowerCase(Locale.ROOT).startsWith("http")) {
            getOrAddNode(href, false, false);
        }
    }

    public void handleReportEvent(String jsonStr) {
        handleReportEvent(jsonStr, 0);
    }

    public void handleReportEvent(String jsonStr, int source) {
        LOGGER.debug("Got event: {}", jsonStr);
        JSONObject json = JSONObject.fromObject(jsonStr);
        ReportedEvent event = new ReportedEvent(json);
        notifyReportedObjectConsumer(event);
        String url = event.getUrl();
        if (url != null && !isApiUrl(url)) {
            setVisited(url);
        }
    }

    private void notifyReportedObjectConsumer(ReportedObject reportObject) {
        if (isApiUrl(reportObject.getUrl())) {
            return;
        }

        if (reportedObjectConsumer != null) {
            reportedObjectConsumer.accept(reportObject);
        }
    }

    private static boolean isApiUrl(String url) {
        return url != null && (url.startsWith(API.API_URL) || url.startsWith(API.API_URL_S));
    }
}

/**
 * Based on example code from: <a
 * href="http://www.java2s.com/Code/Java/Swing-JFC/AtreemodelusingtheSortTreeModelwithaFilehierarchyasinput.htm">Sorted
 * Tree Example</a>
 */
@SuppressWarnings("serial")
class SortedTreeModel extends DefaultTreeModel {

    private static final long serialVersionUID = 4130060741120936997L;
    private Comparator<ClientNode> comparator;

    public SortedTreeModel(TreeNode node, ClientNodeStringComparator siteNodeStringComparator) {
        super(node);
        this.comparator = siteNodeStringComparator;
    }

    public SortedTreeModel(TreeNode node) {
        this(node, new ClientNodeStringComparator());
    }

    public SortedTreeModel(
            TreeNode node, boolean asksAllowsChildren, Comparator<ClientNode> aComparator) {
        super(node, asksAllowsChildren);
        this.comparator = aComparator;
    }

    public void insertNodeInto(ClientNode child, ClientNode parent) {
        int index = findIndexFor(child, parent);
        super.insertNodeInto(child, parent, index);
    }

    public void insertNodeInto(ClientNode child, ClientNode parent, int i) {
        // The index is useless in this model, so just ignore it.
        insertNodeInto(child, parent);
    }

    private int findIndexFor(ClientNode child, ClientNode parent) {
        int childCount = parent.getChildCount();
        if (childCount == 0) {
            return 0;
        }
        if (childCount == 1) {
            return comparator.compare(child, parent.getChildAt(0)) <= 0 ? 0 : 1;
        }
        return findIndexFor(child, parent, 0, childCount - 1);
    }

    private int findIndexFor(ClientNode child, ClientNode parent, int idx1, int idx2) {
        if (idx1 == idx2) {
            return comparator.compare(child, parent.getChildAt(idx1)) <= 0 ? idx1 : idx1 + 1;
        }
        int half = (idx1 + idx2) / 2;
        if (comparator.compare(child, parent.getChildAt(half)) <= 0) {
            return findIndexFor(child, parent, idx1, half);
        }
        return findIndexFor(child, parent, half + 1, idx2);
    }
}

class ClientNodeStringComparator implements Comparator<ClientNode> {
    @Override
    public int compare(ClientNode sn1, ClientNode sn2) {
        if (sn1.isStorage() != sn2.isStorage()) {
            // Always put Storage nodes at the end
            return sn1.isStorage() ? 1 : -1;
        }
        return sn1.getUserObject().getName().compareTo(sn2.getUserObject().getName());
    }
}
