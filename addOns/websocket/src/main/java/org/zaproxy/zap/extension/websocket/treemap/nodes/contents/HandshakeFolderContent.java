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
package org.zaproxy.zap.extension.websocket.treemap.nodes.contents;

import java.util.HashMap;
import java.util.List;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.treemap.nodes.namers.WebSocketNodeNamer;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;

/**
 * This content is used as a folder, meaning that it is not stores significant information. This
 * content provides the appropriate methods to convey the requests to the leaf node.
 */
public class HandshakeFolderContent extends WebSocketContent {

    public HandshakeFolderContent(WebSocketNodeNamer namer) {
        name = namer.getName(this);
    }

    private HandshakeFolderContent(HandshakeFolderContent that) {
        this.name = that.getName();
    }

    @Override
    public HandshakeFolderContent clone() {
        return new HandshakeFolderContent(this);
    }

    @Override
    public List<TreeNode<WebSocketContent>> getHostNodes(
            TreeNode<WebSocketContent> thisNode, List<TreeNode<WebSocketContent>> hostNodesList) {
        if (!thisNode.isRoot() && thisNode.getParent().getContent() != null) {
            return thisNode.getParent().getHostNodes(thisNode.getParent(), hostNodesList);
        }
        return null;
    }

    @Override
    public HashMap<TreeNode<WebSocketContent>, List<WebSocketChannelDTO>> getChannelsPerHost(
            TreeNode<WebSocketContent> thisNode,
            HashMap<TreeNode<WebSocketContent>, List<WebSocketChannelDTO>> channelsMap) {
        thisNode.applyToChildren(t -> t.getChannelsPerHost(t, channelsMap));
        return channelsMap;
    }

    @Override
    public HashMap<TreeNode<WebSocketContent>, List<HistoryReference>>
            getHandshakesReferencesPerHost(
                    TreeNode<WebSocketContent> thisNode,
                    HashMap<TreeNode<WebSocketContent>, List<HistoryReference>> refMap) {
        thisNode.applyToChildren(t -> t.getHandshakesReferencesPerHost(t, refMap));
        return refMap;
    }

    @Override
    public int compareTo(WebSocketContent that) {
        if (that instanceof MessageFolderContent) {
            return 1;
        }
        return super.compareTo(that);
    }
}
