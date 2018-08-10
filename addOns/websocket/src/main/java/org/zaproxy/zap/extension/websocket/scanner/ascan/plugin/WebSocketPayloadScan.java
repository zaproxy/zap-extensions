package org.zaproxy.zap.extension.websocket.scanner.ascan.plugin;

import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketMessageNode;

public abstract class WebSocketPayloadScan extends WebSocketMessageNodeScan {
	
	public abstract void scanPayload(Object message);
	
	public abstract boolean applyScan(Object message);
	
	@Override
	public void scanMessageNode(WebSocketMessageNode messageNode) {
		if(applyScan(messageNode.getWebSocketMessageDTO().payload)){
			scanPayload(messageNode.getWebSocketMessageDTO().payload);
		}
	}
	
	@Override
	public boolean applyScan(WebSocketMessageNode messageNode) {
		return (messageNode.getWebSocketMessageDTO() != null && messageNode.getWebSocketMessageDTO().payload != null) ;
	}
	
}
