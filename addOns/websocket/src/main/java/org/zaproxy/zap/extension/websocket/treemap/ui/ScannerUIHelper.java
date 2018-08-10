package org.zaproxy.zap.extension.websocket.treemap.ui;

import javax.swing.JMenuItem;

public class ScannerUIHelper {
	
	//============= Main WebSocket Popup Menu =================
	private MainWebSocketPopupMenu webSocketPopupMenu = null;
	private JMenuItem ascanItem = null;
	
	public MainWebSocketPopupMenu getWebSocketPopupMenu() {
		if(webSocketPopupMenu == null){
			webSocketPopupMenu = new MainWebSocketPopupMenu();
		}
		return webSocketPopupMenu;
	}
	
	public JMenuItem getActiveScanMenuItem(){
		if(ascanItem == null){
			ascanItem = new JMenuItem("Active Scan"); //TODO
		}
		return ascanItem;
	}
	
	public void addToMenu(JMenuItem jMenuItem){
		getWebSocketPopupMenu().add(jMenuItem);
	}
}
