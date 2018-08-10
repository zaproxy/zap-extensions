package org.zaproxy.zap.extension.websocket.scanner.ascan.plugin;

import org.zaproxy.zap.extension.websocket.treemap.analyzers.PayloadAnalyzer;
import org.zaproxy.zap.extension.websocket.treemap.analyzers.structures.PayloadStructure;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketMessageNode;

public abstract class WebSocketStructureScan extends WebSocketMessageNodeScan {
	
	public abstract void scanMessageStructure(PayloadAnalyzer analyzer, PayloadStructure structure);
	
	public abstract boolean applyScan(PayloadAnalyzer analyzer, PayloadStructure structure);
	
	@Override
	public boolean applyScan(WebSocketMessageNode messageNode) {
		return (messageNode.getPayloadStructure() != null && messageNode.getPayloadAnalyzer() != null);
	}
	
	@Override
	public void scanMessageNode(WebSocketMessageNode messageNode) {
		if(applyScan(messageNode.getPayloadAnalyzer(), messageNode.getPayloadStructure())){
			scanMessageStructure(messageNode.getPayloadAnalyzer(), messageNode.getPayloadStructure());
		}
	}
	
}
