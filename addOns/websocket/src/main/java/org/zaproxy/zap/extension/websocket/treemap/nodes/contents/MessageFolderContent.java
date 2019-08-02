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
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.treemap.nodes.namers.WebSocketNodeNamer;
import org.zaproxy.zap.extension.websocket.treemap.nodes.structural.TreeNode;

/**
 * This content is used as a folder, meaning that it is not stores significant information. This
 * content provides the appropriate methods to convey the requests to the leaf node. There are
 * different {@link Type} of folders.
 */
public class MessageFolderContent extends WebSocketContent implements Cloneable {

    private Type type;

    public MessageFolderContent(WebSocketNodeNamer namer, Integer opcode) {
        this.type = Type.getType(opcode);
        name = namer.getName(this);
    }

    private MessageFolderContent(MessageFolderContent that) {
        this.type = that.getType();
        this.name = that.getName();
    }

    public Type getType() {
        return type;
    }

    @Override
    public List<TreeNode<WebSocketContent>> getHostNodes(
            TreeNode<WebSocketContent> thisNode, List<TreeNode<WebSocketContent>> hostNodesList) {
        if (thisNode.getParent() != null && thisNode.getParent().getContent() != null) {
            return thisNode.getParent().getHostNodes(thisNode.getParent(), hostNodesList);
        }
        return null;
    }

    @Override
    public HashMap<TreeNode<WebSocketContent>, List<WebSocketMessageDTO>> getMessagesPerHost(
            TreeNode<WebSocketContent> thisNode,
            HashMap<TreeNode<WebSocketContent>, List<WebSocketMessageDTO>> messageMap) {

        if (thisNode.isLeaf()) return messageMap;

        thisNode.applyToChildren(t -> t.getMessagesPerHost(t, messageMap));
        return messageMap;
    }

    /**
     * Compares the {@link MessageFolderContent} according to their {@link Type#order}. Also
     * compares this content with the {@link HandshakeFolderContent} which are always going first.
     *
     * @param that The content is going to be compared with this object.
     * @return
     */
    @Override
    public int compareTo(WebSocketContent that) {
        if (that instanceof MessageFolderContent) {
            return ((MessageFolderContent) that).getType().getOrder() - this.getType().getOrder();
        }
        if (that instanceof HandshakeFolderContent) {
            return -1;
        }
        return super.compareTo(that);
    }

    @Override
    public WebSocketContent clone() {
        return new MessageFolderContent(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        MessageFolderContent that = (MessageFolderContent) o;
        return type == that.type && this.compareTo(that) == 0;
    }

    public MessageFolderContent replaceValues(WebSocketNodeNamer namer, Integer opcode) {
        this.type = Type.getType(opcode);
        name = namer.getName(this);
        return this;
    }
}
