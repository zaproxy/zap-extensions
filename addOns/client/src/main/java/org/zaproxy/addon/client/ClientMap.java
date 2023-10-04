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

import java.util.Comparator;
import java.util.Locale;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreeNode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@SuppressWarnings("serial")
public class ClientMap extends SortedTreeModel {

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LogManager.getLogger(ClientMap.class);
    private ClientNode root;

    public ClientMap(ClientNode root) {
        super(root);
        this.root = root;
    }

    @Override
    public ClientNode getRoot() {
        return root;
    }

    public synchronized ClientNode getOrAddNode(String url, boolean visited, boolean storage) {
        LOGGER.debug("getOrAddNode {}", url);
        if (url == null) {
            throw new IllegalArgumentException("The url parameter should not be null");
        }
        // Parse the URL into its component pieces
        String urlLc = url.toLowerCase(Locale.ROOT);
        if (!(urlLc.startsWith("http://") || urlLc.startsWith("https://"))) {
            throw new IllegalArgumentException(
                    "The url parameter must start with 'http://' or 'https://' - was " + urlLc);
        }
        int offset = url.indexOf("//") + 2;
        String prefix = url.substring(0, offset);

        String queryString = "";
        int queryOffset = url.indexOf('?');
        if (queryOffset > 0) {
            queryString = url.substring(queryOffset);
            url = url.substring(0, queryOffset);
        }

        ClientNode parent = root;
        ClientNode child = null;
        String[] components = url.substring(offset).split("/");
        for (int i = 0; i < components.length; i++) {
            String component = prefix + components[i];
            boolean isLastComponent = i == components.length - 1;
            if (isLastComponent) {
                // TODO just extract param names...
                component += queryString;
            }
            prefix = "";
            LOGGER.debug("component {}", component);
            boolean foundParent = false;
            for (int j = 0; j < parent.getChildCount(); j++) {
                child = parent.getChildAt(j);
                if ((!isLastComponent || storage == child.isStorage())
                        && component.equals(child.getUserObject().getName())) {
                    foundParent = true;
                    break;
                }
            }
            if (!foundParent) {
                String parentUrl;
                if (parent.isRoot()) {
                    parentUrl = component + "/";
                } else {
                    String pUrl = parent.getUserObject().getUrl();
                    if (!pUrl.endsWith("/")) {
                        pUrl += "/";
                    }
                    parentUrl = pUrl + component;
                    if (!isLastComponent) {
                        parentUrl += "/";
                    }
                }
                child =
                        new ClientNode(
                                new ClientSideDetails(component, parentUrl, visited, storage),
                                storage);
                this.insertNodeInto(child, parent);
                this.nodeStructureChanged(parent);
            }
            parent = child;
        }
        if (child == null) {
            throw new IllegalArgumentException("No userObject set for node with url " + url);
        }

        return child;
    }

    public void clear() {
        root.removeAllChildren();
        this.nodeStructureChanged(root);
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
