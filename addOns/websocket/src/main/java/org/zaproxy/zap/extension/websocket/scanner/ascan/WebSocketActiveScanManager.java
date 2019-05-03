package org.zaproxy.zap.extension.websocket.scanner.ascan;

import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.websocket.scanner.ascan.plugin.WebSocketActivePlugin;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketTreeNode;

public class WebSocketActiveScanManager {
	
	
	private static Logger LOGGER = Logger.getLogger(WebSocketPluginFactory.class);
	
	private WebSocketScanner webSocketScanner;
	private WebSocketPluginFactory webSocketPluginFactory = null;
	private boolean isEnabled = true;
	private Thread thread = null;
	
	public WebSocketActiveScanManager(){
		LOGGER.warn("WORKS");
		webSocketScanner = new WebSocketScanner(this);
	}
	
	public void addPlugin(WebSocketActivePlugin plugin){
		getWebSocketPluginFactory().addPlugin(plugin);
	}
	
	public void setActiveScanEnabled(boolean isEnabled){
		this.isEnabled = isEnabled;
	}
	
	public boolean isEnabled(){
		return isEnabled;
	}
	
	public void setAllPluginEnabled(boolean isEnabled){
		getWebSocketPluginFactory().setAllEnabled(isEnabled);
	}
	
	public void removePlugin(WebSocketActivePlugin plugin){
		getWebSocketPluginFactory().removePlugin(plugin);
	}
	
	public WebSocketPluginFactory getWebSocketPluginFactory(){
		if(webSocketPluginFactory == null){
			webSocketPluginFactory = new WebSocketPluginFactory();
		}
		return webSocketPluginFactory;
	}
	
	public int startScan(WebSocketTreeNode webSocketTreeNode, boolean recurse){
		if(thread != null && thread.isAlive()){
			return -1;
		}
		
		thread = new Thread(webSocketScanner);
		
		WebSocketTarget webSocketTarget = new WebSocketTarget(webSocketTreeNode,recurse);
		webSocketScanner.setTarget(webSocketTarget);
			
		thread.setPriority(Thread.NORM_PRIORITY-2);
		thread.start();
		return 0;
	}
}
