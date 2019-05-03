package org.zaproxy.zap.extension.websocket.scanner.ascan;


import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.websocket.scanner.ascan.plugin.WebSocketActivePlugin;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketNodeType;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;

public class WebSocketPluginFactory {
	
	private static Logger LOGGER = Logger.getLogger(WebSocketPluginFactory.class);
	
	private LinkedHashMap<Integer, WebSocketActivePlugin> scannerPlugin;
	private LinkedHashMap<Integer,WebSocketActivePlugin> pendingPlugin;
	
	public WebSocketPluginFactory(){
		scannerPlugin = new LinkedHashMap<>();
		pendingPlugin = new LinkedHashMap<>();
	}
	
	public void addPlugin(WebSocketActivePlugin plugin) {
		LOGGER.info("An Plugin added: " + plugin.getName());
		scannerPlugin.put(plugin.getCode(), plugin);
	}
	
	public LinkedHashMap<Integer, WebSocketActivePlugin> getPendingPlugin() {
		return pendingPlugin;
	}
	
	public void reset(){
		pendingPlugin.clear();
	}
	
	public void removePlugin(WebSocketActivePlugin plugin){
		scannerPlugin.remove(plugin);
	}
	
	public void setAllEnabled(boolean isEnabled){
		for(WebSocketActivePlugin plugin : scannerPlugin.values()){
			plugin.setEnabled(isEnabled);
		}
	}
	
	public Collection<WebSocketActivePlugin> getPluginList(){
		return  scannerPlugin.values();
	}
	
	public List<WebSocketActivePlugin> getSuitablePlugin(WebSocketNodeType nodeType){
		
		List<WebSocketActivePlugin> suitablePlugins = new ArrayList<>();
		
		for(WebSocketActivePlugin plugin : scannerPlugin.values()){
			if (plugin.canScan(nodeType)){
				try {
					if(pendingPlugin.containsKey(plugin.getCode())){
						suitablePlugins.add(pendingPlugin.get(plugin.getCode()));
					}else{
						suitablePlugins.add(plugin.getClass().getDeclaredConstructor().newInstance());
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
		return suitablePlugins;
	}
	
	private void addToPendingPlugin(int id){
		pendingPlugin.put(id,scannerPlugin.get(id));
	}
	
	public WebSocketActivePlugin getPendingPlugin(int id) {
		return pendingPlugin.get(id);
	}
}
