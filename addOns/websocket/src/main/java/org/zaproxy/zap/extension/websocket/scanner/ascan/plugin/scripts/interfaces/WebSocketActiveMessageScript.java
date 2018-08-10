package org.zaproxy.zap.extension.websocket.scanner.ascan.plugin.scripts.interfaces;

import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.scanner.ascan.plugin.scripts.ScriptWebSocketMessageActivePlugin;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketMessageNode;

public interface WebSocketActiveMessageScript {
	
	void scan(WebSocketMessageNode webSocketMessageNode, ScriptWebSocketMessageActivePlugin parent);
	
	default boolean applyScan(WebSocketMessageNode webSocketMessageNode){
		return true;
	}
	
	void messageReceived(WebSocketMessageDTO message);
	
	void connectionStateChanged(WebSocketProxy.State state);
	
}
