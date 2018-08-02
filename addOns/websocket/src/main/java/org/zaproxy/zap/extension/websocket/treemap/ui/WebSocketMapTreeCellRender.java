package org.zaproxy.zap.extension.websocket.treemap.ui;

import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketNodeType;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.OverlayIcon;

import javax.swing.ImageIcon;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTree;
import javax.swing.tree.DefaultTreeCellRenderer;
import java.awt.Component;
import java.awt.FlowLayout;

public class WebSocketMapTreeCellRender extends DefaultTreeCellRenderer {
	
	private static final long serialVersionUID = -427869101224513123L;
	
	private static final ImageIcon FOLDER_ROOT_ICON = new ImageIcon(WebSocketMapTreeCellRender.class.getResource("/resource/icon/16/094.png"));
	private static final ImageIcon FOLDER_HANSHAKE_ICON = new ImageIcon(WebSocketMapTreeCellRender.class.getResource("/resource/icon/fugue/folder-horizontal.png"));
	private static final ImageIcon HANSHAKE_ICON = new ImageIcon(WebSocketMapTreeCellRender.class.getResource("/org/zaproxy/zap/extension/websocket/resources/icons/hand-shake.png"));
	private static final ImageIcon FOLDER_CLOSE_ICON     = new ImageIcon(WebSocketMapTreeCellRender.class.getResource("/org/zaproxy/zap/extension/websocket/resources/icons/plug-disconnect.png"));
	private static final ImageIcon FOLDER_HEARTBEAT_ICON = new ImageIcon(WebSocketMapTreeCellRender.class.getResource("/org/zaproxy/zap/extension/websocket/resources/icons/heart.png"));
	private static final ImageIcon FOLDER_CONNECTED_CHANNEL_ICON = new ImageIcon(WebSocketMapTreeCellRender.class.getResource("/resource/icon/fugue/plug-connect.png"));
	private static final ImageIcon FOLDER_DISCONNECTED_CHANNEL_ICON = new ImageIcon(WebSocketMapTreeCellRender.class.getResource("/resource/icon/fugue/plug-disconnect.png"));
	private static final ImageIcon FOLDER_MESSAGES_ICON  = new ImageIcon(WebSocketMapTreeCellRender.class.getResource("/resource/icon/16/004.png"));
	
	private static Logger LOGGER = Logger.getLogger(WebSocketMapTreeCellRender.class);
	
//	private List<SiteMapListener> listeners;
	private JPanel component;
	
	public WebSocketMapTreeCellRender(){
//		this.listeners = listeners;
		this.component = new JPanel(new FlowLayout(FlowLayout.CENTER,4,2));
		component.setOpaque(false);
	}
	
	/**
	 * Sets custom tree node logos.
	 */
	@Override
	public Component getTreeCellRendererComponent(JTree tree, Object value,
												  boolean sel, boolean expanded, boolean leaf, int row,
												  boolean hasFocus) {
		component.removeAll();
		WebSocketNodeUI webSocketNodeUI = (WebSocketNodeUI) value;
		
		if(webSocketNodeUI != null) {
			setPreferredSize(null);	// clears the preferred size, making the node visible
			super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
			
			OverlayIcon icon = null;
			
			if (webSocketNodeUI.isRoot()) {
				LOGGER.info("[WS-TREE]: FOLDER ROOT");
				component.add(wrap(FOLDER_ROOT_ICON)); // 'World' icon
			}else{
				
				
				WebSocketNodeType webSocketNodeType = webSocketNodeUI.getNodeType();
				switch (webSocketNodeType) {
					case FOLDER_MESSAGES:
						icon = new OverlayIcon(FOLDER_MESSAGES_ICON);
						break;
					case FOLDER_HOST:
						if(webSocketNodeUI.getWebSocketNode().isConnected()){
							icon = new OverlayIcon(FOLDER_CONNECTED_CHANNEL_ICON);
						}else {
							icon = new OverlayIcon(FOLDER_DISCONNECTED_CHANNEL_ICON);
						}
						break;
					case FOLDER_ROOT:
						icon = new OverlayIcon(FOLDER_ROOT_ICON);
						break;
					case FOLDER_HANDSHAKES:
						icon = new OverlayIcon(FOLDER_HANSHAKE_ICON);
						break;
					case FOLDER_HEARTBEATS:
						icon = new OverlayIcon(FOLDER_HEARTBEAT_ICON);
						break;
					case FOLDER_CLOSE:
						icon = new OverlayIcon(FOLDER_CLOSE_ICON);
						break;
					case HANDSHAKE:
						icon = new OverlayIcon(HANSHAKE_ICON);
						break;
						
				}
				
				component.add(wrap(DisplayUtils.getScaledIcon(icon)));
			}
			
			for (ImageIcon ci : webSocketNodeUI.getCustomIcons()) {
				component.add(wrap(DisplayUtils.getScaledIcon(ci)));
			}
			
			setText(webSocketNodeUI.toString());
			setIcon(null);
			component.add(this);
			
			return component;
		}
		return this;
	}
	
	private JLabel wrap (ImageIcon icon) {
		JLabel label = new JLabel(icon);
		label.setOpaque(false);
		label.putClientProperty("html.disable", Boolean.TRUE);
		return label;
	}
	
}
