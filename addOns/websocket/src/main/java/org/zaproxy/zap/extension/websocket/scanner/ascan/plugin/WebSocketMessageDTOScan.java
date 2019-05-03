package org.zaproxy.zap.extension.websocket.scanner.ascan.plugin;

import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketMessageNode;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketNodeType;

import java.util.Arrays;
import java.util.HashSet;

public abstract class WebSocketMessageDTOScan extends WebSocketMessageNodeScan {
	
	public static final WebSocketNodeType[] TYPES =
			new WebSocketNodeType[]{ WebSocketNodeType.MESSAGE_OBJECT, WebSocketNodeType.MESSAGE_TEXT};
	public static final HashSet<WebSocketNodeType> TYPE_SET = new HashSet<>(Arrays.asList(TYPES));
	
	@Override
	public boolean canScan(WebSocketNodeType type){
		return TYPE_SET.contains(type);
	}
	
	public abstract void scanMessage(WebSocketMessageDTO message);
	
	public abstract boolean applyScan(WebSocketMessageDTO message);
	
	@Override
	public abstract void messageReceived(WebSocketMessageDTO message);
	
	@Override
	public abstract void connectionStateChanged(WebSocketProxy.State state, WebSocketProxy proxy);
	
	@Override
	public void scanMessageNode(WebSocketMessageNode messageNode) {
		if(applyScan(messageNode.getWebSocketMessageDTO())){
			scanMessage(messageNode.getWebSocketMessageDTO());
		}
	}
	
	@Override
	public boolean applyScan(WebSocketMessageNode messageNode) {
		return messageNode.getWebSocketMessageDTO() != null;
	}
}
