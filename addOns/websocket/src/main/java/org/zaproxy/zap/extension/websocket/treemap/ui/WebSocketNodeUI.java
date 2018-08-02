package org.zaproxy.zap.extension.websocket.treemap.ui;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.treemap.nodes.StructuralWebSocketNode;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketMessageNode;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketNodeType;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketTreeNode;

import javax.swing.*;
import javax.swing.tree.DefaultMutableTreeNode;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class WebSocketNodeUI extends DefaultMutableTreeNode {
	
	private static final long serialVersionUID = 8108466538763097835L;
	
	private static Logger LOGGER = Logger.getLogger(WebSocketNodeUI.class);
	
	private WebSocketTreeNode webSocketTreeNode;
	private ArrayList<String> icons;
	
	private static final String INCOMING_MESSAGE_ICON = "/resource/icon/105_gray.png";
	private static final String OUTGOING_MESSAGE_ICON = "/resource/icon/106_gray.png";
	
	public WebSocketNodeUI(WebSocketTreeNode webSocketTreeNode){
		super();
		this.webSocketTreeNode = webSocketTreeNode;
		icons = new ArrayList<>();
		if(webSocketTreeNode instanceof WebSocketMessageNode){
			WebSocketMessageDTO message = webSocketTreeNode.getWebSocketMessageDTO();
			if(message.isOutgoing){
				addCustomIcon(OUTGOING_MESSAGE_ICON);
			}else{
				addCustomIcon(INCOMING_MESSAGE_ICON);
			}
		}
		icons = new ArrayList<>();
	}
	
	public StructuralWebSocketNode getWebSocketNode(){
		return webSocketTreeNode;
	}
	
	public void setCustomIcons(ArrayList<String> i, ArrayList<Boolean> c) {
		synchronized (this.icons) {
			this.icons.clear();
			this.icons.addAll(i);
		}
	}
	
	public void addCustomIcon(String resourceName) {
		synchronized (this.icons) {
			if (! this.icons.contains(resourceName)) {
				this.icons.add(resourceName);
				this.nodeChanged();
			}
		}
	}
	
	public void removeCustomIcon(String resourceName) {
		synchronized (this.icons) {
			if (this.icons.contains(resourceName)) {
				int i = this.icons.indexOf(resourceName);
				this.icons.remove(i);
//				this.nodeChanged();
			}
		}
	}
	
	
	/**
	 * Gets any custom icons that have been set for this node
	 * @return any custom icons that have been set for this node
	 * @since 2.6.0
	 */
	public List<ImageIcon> getCustomIcons() {
		List<ImageIcon> iconList = new ArrayList<>();
		synchronized (this.icons) {
			if (!this.icons.isEmpty()) {
				for(String icon : this.icons) {
					iconList.add(new ImageIcon(Constant.class.getResource(icon)));
				}
			}
		}
		return iconList;
	}
	
	@Override
	public String toString() {
		return webSocketTreeNode.getNodeName();
	}
	
	private void nodeChanged() {
		if (EventQueue.isDispatchThread()) {
			nodeChangedEventHandler();
		} else {
			try {
				EventQueue.invokeLater(new Runnable() {
					@Override
					public void run() {
						nodeChangedEventHandler();
					}
				});
			} catch (Exception e) {
				LOGGER.error(e.getMessage(), e);
			}
		}
	}
	
	private void nodeChangedEventHandler() {
//		this.siteMap.nodeChanged(this);
	}
	
	public WebSocketNodeType getNodeType(){
		return webSocketTreeNode.getNodeType();
	}
	
	public int[] getNodeIndex(){
		return webSocketTreeNode.getNodeIndex();
	}
	
}
