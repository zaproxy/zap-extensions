package org.zaproxy.zap.extension.websocket.scanner.ascan.plugin;

import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.client.HandshakeConfig;
import org.zaproxy.zap.extension.websocket.client.RequestOutOfScopeException;
import org.zaproxy.zap.extension.websocket.scanner.ascan.WebSocketHostProcess;
import org.zaproxy.zap.extension.websocket.scanner.ascan.WebSocketTarget;
import org.zaproxy.zap.extension.websocket.treemap.nodes.StructuralWebSocketNode;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketNodeType;
import org.zaproxy.zap.utils.Enableable;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.Callable;

public abstract class WebSocketActivePlugin extends Enableable implements Callable<Integer> {
	
	private static Logger LOGGER = Logger.getLogger(WebSocketActivePlugin.class);
	
	public static final WebSocketNodeType[] TYPES =
			new WebSocketNodeType[]{WebSocketNodeType.HANDSHAKE, WebSocketNodeType.MESSAGE_OBJECT, WebSocketNodeType.MESSAGE_TEXT};
	public static final HashSet<WebSocketNodeType> TYPE_SET = new HashSet<>(Arrays.asList(TYPES));
	
	private WebSocketHostProcess parent;
	private boolean isEnable = true;
	private List<WebSocketTarget> targets;
	private Date started = null;
	private Date finished = null;
	
	public void setParent(WebSocketHostProcess parent) {
		this.parent = parent;
	}
	
	public void addTarget(WebSocketTarget target) {
		if(targets == null){
			targets = new ArrayList<>();
		}
		targets.add(target);
		LOGGER.info("A new Target Added");
	}
	
	protected WebSocketProxy sendHandshake(HandshakeConfig handshakeConfig) throws IOException, RequestOutOfScopeException {
		return parent.getConnectionEstablisher().send(handshakeConfig);
	}
	
	protected WebSocketProxy getConnection() throws IOException, RequestOutOfScopeException {
		return parent.getActiveConnection(this);
	}
	
	public void sendMessage(WebSocketMessageDTO message) throws IOException, RequestOutOfScopeException {
		WebSocketProxy connection = parent.getActiveConnection(this);
		
		message.channel = connection.getDTO();
		message.isOutgoing = true;
		message.hasChanged = true;
		connection.send(message,WebSocketProxy.Initiator.MANUAL_REQUEST);
	}
	
	public boolean canScan(WebSocketNodeType type){
		return TYPE_SET.contains(type);
	}
	
	public abstract void messageReceived(WebSocketMessageDTO message);
	
	public abstract void connectionStateChanged(WebSocketProxy.State state, WebSocketProxy proxy);
	
	public abstract void scanNode(StructuralWebSocketNode structuralWebSocketNode);
	
	public abstract boolean applyScan(StructuralWebSocketNode structuralWebSocketNode);
	
	public abstract String getName();
	
	public abstract int getCode();
	
	@Override
	public Integer call() {
		LOGGER.info("CALL Active Scan");
		for(WebSocketTarget target : targets){
			LOGGER.info("Scan Target: " + target.getStartingNode().getNodeName());
			if(applyScan(target.getStartingNode())){
				LOGGER.info("Scan Applied");
				scanNode(target.getStartingNode());
			}
		}
		return null;
	}
	
}
