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

import java.util.ArrayList;
import java.util.List;
import javax.swing.tree.DefaultMutableTreeNode;
import org.parosproxy.paros.model.Session;

@SuppressWarnings("serial")
public class ClientNode extends DefaultMutableTreeNode {

    private static final long serialVersionUID = 1L;
    private boolean storage;
    private Session session;

    public ClientNode(ClientSideDetails userObject, Session session) {
        super(userObject);
        this.session = session;
    }

    public ClientNode(ClientSideDetails userObject, boolean storage) {
        super(userObject);
        this.storage = storage;
    }

    @Override
    public ClientSideDetails getUserObject() {
        return (ClientSideDetails) super.getUserObject();
    }

    @Override
    public ClientNode getParent() {
        return (ClientNode) super.getParent();
    }

    @Override
    public ClientNode getChildAt(int index) {
        return (ClientNode) super.getChildAt(index);
    }

    public ClientNode getChild(String name, boolean isStorage) {
        for (int i = 0; i < getChildCount(); i++) {
            ClientNode child = getChildAt(i);
            if (isStorage == child.isStorage() && name.equals(child.getUserObject().getName())) {
                return child;
            }
        }
        return null;
    }

    public boolean isStorage() {
        return storage;
    }

    public String getSite() {
        ClientNode parent = this.getParent();
        if (parent.isRoot()) {
            return this.getUserObject().getUrl();
        }
        return parent.getSite();
    }

    public Session getSession() {
        if (session != null) {
            return session;
        }
        ClientNode parent = getParent();
        if (parent != null) {
            return parent.getSession();
        }
        return null;
    }

    /**
     * A diagnostic method which returns a List of strings which represent the node and optionally
     * its children. To get a String representation use something like:
     *
     * <p>{@code String.join("\n", node.getNodeSummary(null, 0, true));}
     *
     * @param summary the list to use, if null a new list will be created
     * @param indent the level to indent - typically you will want to supply 0
     * @param recurse if true then will recurse through the child nodes as well
     * @return a list of strings representing the node
     */
    public List<String> getNodeSummary(List<String> summary, int indent, boolean recurse) {
        if (summary == null) {
            summary = new ArrayList<>();
        }
        if (isRoot()) {
            summary.add("Node name: Root");
        } else {
            String indentStr = " ".repeat(indent);
            summary.add(indentStr + "Node name: " + this.getUserObject().getName());
            summary.add(indentStr + "      url: " + this.getUserObject().getUrl());
            summary.add(indentStr + "  storage: " + this.getUserObject().isStorage());
            summary.add(indentStr + "  visited: " + this.getUserObject().isVisited());
        }
        if (recurse) {
            for (int i = 0; i < this.getChildCount(); i++) {
                this.getChildAt(i).getNodeSummary(summary, indent + 1, true);
            }
        }
        return summary;
    }

    @Override
    public String toString() {
        return getUserObject().getUrl();
    }
}
