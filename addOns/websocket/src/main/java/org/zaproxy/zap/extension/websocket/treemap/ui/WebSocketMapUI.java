package org.zaproxy.zap.extension.websocket.treemap.ui;

import org.apache.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.websocket.treemap.WebSocketMap;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketNodeObserver;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketTreeNode;

import javax.swing.tree.DefaultTreeModel;
import java.util.List;

public class WebSocketMapUI extends DefaultTreeModel implements WebSocketNodeObserver {
	
	private static final long serialVersionUID = 5246172770195902240L;
	
	private static final Logger LOGGER = Logger.getLogger(WebSocketMapUI.class);
	
	private WebSocketNodeUI root;
	private WebSocketMap webSocketMap;
	private Model model;
	
	public WebSocketMapUI(WebSocketNodeUI root, WebSocketMap webSocketMap, Model model) {
		super(root);
		this.webSocketMap = webSocketMap;
		this.root = root;
		this.model = model;
	}
	
	static public WebSocketMapUI createTreeUI(WebSocketMap websocketMap, Model model){
		return new WebSocketMapUI(new WebSocketNodeUI(websocketMap.getRoot()), websocketMap, model);
	}
	
	public void insertNodeInto(WebSocketNodeUI child, WebSocketNodeUI parent, int[] index) {
		WebSocketNodeUI currentNode = parent;
		for(int i = parent.getNodeIndex().length ; i < index.length; i++){
			if(i + 1 == index.length){
				super.insertNodeInto(child,currentNode,index[i]);
			}else{
				currentNode = (WebSocketNodeUI) currentNode.getChildAt(index[i]);
			}
		}
	}
	
	@Override
	public void nodesAdded(List<WebSocketTreeNode> webSocketTreeNodes) {
		for(WebSocketTreeNode webSocketTreeNode : webSocketTreeNodes){
			System.out.println( "Name :" + webSocketTreeNode.getNodeName() + " Index" + webSocketTreeNode.getNodeIndex().toString());
			insertNodeInto(new WebSocketNodeUI(webSocketTreeNode), root, webSocketTreeNode.getNodeIndex());
		}
	}
	
	@Override
	public void nodeAdded(WebSocketTreeNode webSocketTreeNode) {
		System.out.println( "Name :" + webSocketTreeNode.getNodeName() + " Index" + webSocketTreeNode.getNodeIndex().toString());
		insertNodeInto(new WebSocketNodeUI(webSocketTreeNode), root, webSocketTreeNode.getNodeIndex());
	}
	
	@Override
	public void nodeDeleted(WebSocketTreeNode webSocketTreeNode) {
	
	}
	
	@Override
	public void nodesDeleted(List<WebSocketTreeNode> webSocketTreeNodes) {
	
	}
	
	public WebSocketNodeUI findByNode(WebSocketTreeNode webSocketTreeNode, WebSocketNodeUI parent){
		return null;
	}
}
