/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket.treemap.ui;

import java.util.ArrayList;
import java.util.List;
import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.tree.TreeModel;

public abstract class WebSocketTreeModelAbstract implements TreeModel {

    private List<TreeModelListener> treeModelListeners;

    public WebSocketTreeModelAbstract() {
        this.treeModelListeners = new ArrayList<>();
    }

    protected void fireTreeNodesChanged(TreeModelEvent event) {
        for (TreeModelListener listener : treeModelListeners) {
            listener.treeNodesChanged(event);
        }
    }

    protected void fireTreeNodesInserted(TreeModelEvent event) {
        for (TreeModelListener listener : treeModelListeners) {
            listener.treeNodesInserted(event);
        }
    }

    protected void fireTreeNodesRemoved(TreeModelEvent event) {
        for (TreeModelListener listener : treeModelListeners) {
            listener.treeNodesRemoved(event);
        }
    }

    protected void fileTreeStructureChanged(TreeModelEvent event) {
        for (TreeModelListener listener : treeModelListeners) {
            listener.treeStructureChanged(event);
        }
    }

    @Override
    public void addTreeModelListener(TreeModelListener treeModelListener) {
        treeModelListeners.add(treeModelListener);
    }

    @Override
    public void removeTreeModelListener(TreeModelListener treeModelListener) {
        treeModelListeners.remove(treeModelListener);
    }
}
