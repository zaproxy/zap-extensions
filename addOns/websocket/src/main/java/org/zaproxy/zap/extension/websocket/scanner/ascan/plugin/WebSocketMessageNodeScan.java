package org.zaproxy.zap.extension.websocket.scanner.ascan.plugin;

import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.websocket.treemap.nodes.StructuralWebSocketNode;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketMessageNode;

import java.util.Iterator;

public abstract class WebSocketMessageNodeScan extends WebSocketActivePlugin{
	
	private static final Logger LOGGER = Logger.getLogger(WebSocketMessageNodeScan.class);
	
	public abstract void scanMessageNode(WebSocketMessageNode messageNode);
	
	public abstract boolean applyScan(WebSocketMessageNode messageNode);
	
	@Override
	public void scanNode(StructuralWebSocketNode structuralWebSocketNode) {
		LOGGER.info("Scan Node: " + structuralWebSocketNode.getNodeName());
		Iterator<StructuralWebSocketNode> iterator = structuralWebSocketNode.getChildrenIterator();
		if(applyScan( (WebSocketMessageNode) structuralWebSocketNode)){
			scanMessageNode((WebSocketMessageNode) structuralWebSocketNode);
		}
	}
	
	@Override
	public boolean applyScan(StructuralWebSocketNode structuralWebSocketNode) {
		LOGGER.info("Apply Scan" +
				"");
		return (structuralWebSocketNode instanceof WebSocketMessageNode);
	}
}
