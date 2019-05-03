package org.zaproxy.zap.extension.websocket.scanner.ascan;

import org.zaproxy.zap.extension.websocket.client.HandshakeConfig;
import org.zaproxy.zap.extension.websocket.treemap.nodes.StructuralWebSocketNode;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class WebSocketTarget {
	
	private boolean isRecurse;
	private StructuralWebSocketNode startingNode;
	private List<StructuralWebSocketNode> nodesForScanning;
	private HandshakeConfig handshakeConfig;
	
	public WebSocketTarget(StructuralWebSocketNode startingNode, boolean recurse){
		this.startingNode = startingNode;
		this.isRecurse = recurse;
	}
	
	public boolean isRecurse() {
		return isRecurse;
	}
	
	public StructuralWebSocketNode getStartingNode() {
		return startingNode;
	}
	
	public List<StructuralWebSocketNode> getNodesForScanning() {
		if(nodesForScanning == null){
			nodesForScanning = new ArrayList<>();
		}else{
			return nodesForScanning;
		}
		
		if(!isRecurse){
			nodesForScanning.add(startingNode);
		}else{
			recursiveAddList(startingNode);
		}
		return nodesForScanning;
	}
	
	private void recursiveAddList(StructuralWebSocketNode node){
		if(node == null){
			return;
		}
		
		if(!node.getNodeType().isFolder()){
			nodesForScanning.add(node);
		}
		
		if(node.getChildren().size() > 0){
			Iterator<StructuralWebSocketNode> iterator = node.getChildrenIterator();
			while (iterator.hasNext()){
				recursiveAddList(node);
			}
		}
	}
}
