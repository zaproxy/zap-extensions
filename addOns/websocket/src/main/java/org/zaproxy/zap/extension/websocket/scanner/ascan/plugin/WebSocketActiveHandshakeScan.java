package org.zaproxy.zap.extension.websocket.scanner.ascan.plugin;

import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.client.HandshakeConfig;
import org.zaproxy.zap.extension.websocket.client.RequestOutOfScopeException;
import org.zaproxy.zap.extension.websocket.treemap.nodes.StructuralWebSocketNode;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketHandshakeNode;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketNodeType;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;

public abstract class WebSocketActiveHandshakeScan extends WebSocketActivePlugin{
	
	public static final WebSocketNodeType[] TYPES = new WebSocketNodeType[]{WebSocketNodeType.HANDSHAKE};
	public static final HashSet<WebSocketNodeType> TYPE_SET = new HashSet<>(Arrays.asList(TYPES));
	
	public HttpMessage sendAndReceive(HandshakeConfig handshakeConfig) throws IOException, RequestOutOfScopeException, DatabaseException {
		WebSocketProxy webSocketProxy = super.sendHandshake(handshakeConfig);
		return webSocketProxy.getHandshakeReference().getHttpMessage();
	}
	
	public abstract void scanHandshake(HttpMessage handshake);
	
	public abstract boolean applyScanToHandshake(HttpMessage handshake);
	
	@Override
	public boolean canScan(WebSocketNodeType type) {
		return TYPE_SET.contains(type);
	}
	
	@Override
	public void scanNode(StructuralWebSocketNode structuralWebSocketNode){
		WebSocketHandshakeNode webSocketHandshakeNode = (WebSocketHandshakeNode) structuralWebSocketNode;
		
		try {
			HttpMessage httpHandshake = webSocketHandshakeNode.getHandshakeRef().getHttpMessage();
			if(applyScanToHandshake(httpHandshake)){
				scanHandshake(httpHandshake);
			}
		} catch (HttpMalformedHeaderException e) {
			e.printStackTrace();
		} catch (DatabaseException e) {
			e.printStackTrace();
		}
		
	}
	
	@Override
	public boolean applyScan(StructuralWebSocketNode structuralWebSocketNode) {
		return (structuralWebSocketNode.getNodeType() == WebSocketNodeType.HANDSHAKE
				&& structuralWebSocketNode.getNodeType() == WebSocketNodeType.FOLDER_HANDSHAKES);
	}
	
	@Override
	public int getCode() {
		return 0;
	}
}
