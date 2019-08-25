package org.zaproxy.zap.extension.websocket.treemap.nodes;

import java.util.List;

public interface WebSocketNodeObserver {
	void nodesAdded(List<WebSocketTreeNode> webSocketTreeNodes);
	void nodeAdded(WebSocketTreeNode  webSocketTreeNode);
	void nodeDeleted(WebSocketTreeNode webSocketTreeNode);
	void nodesDeleted(List<WebSocketTreeNode> webSocketTreeNodes);
}
