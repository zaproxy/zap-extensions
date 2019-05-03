package org.zaproxy.zap.extension.websocket.scanner.ascan;

import org.apache.commons.collections.BidiMap;
import org.apache.commons.collections.bidimap.DualHashBidiMap;
import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.websocket.WebSocketMessage;
import org.zaproxy.zap.extension.websocket.WebSocketObserver;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.extension.websocket.client.HandshakeConfig;
import org.zaproxy.zap.extension.websocket.client.RequestOutOfScopeException;
import org.zaproxy.zap.extension.websocket.client.ServerConnectionEstablisher;
import org.zaproxy.zap.extension.websocket.scanner.ascan.plugin.WebSocketActivePlugin;
import org.zaproxy.zap.extension.websocket.treemap.nodes.StructuralWebSocketNode;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.Executors;

public class WebSocketHostProcess implements Callable<Integer>, WebSocketObserver {
	
	private static Logger LOGGER = Logger.getLogger(WebSocketHostProcess.class);
	
	private WebSocketScanner parentScanner;
	private WebSocketTarget target;
	private ServerConnectionEstablisher connectionEstablisher;
	private HandshakeConfig handshakeConfig;
	private BidiMap activeConnections;
	private HashMap<Integer, WebSocketProxy> channelProxyMap;
	private long hostProcessStartTime = 0;
	private Executor executorService;
	private ExecutorCompletionService<Integer> executorCompletionService;
//	private HashMap<Integer, WebSocketActivePlugin> pendingPlugin;
	
	public WebSocketHostProcess(WebSocketScanner parentScanner, WebSocketTarget target){
		LOGGER.info("A new HostProcess with starting node: " + target.getStartingNode().getNodeName());
		
		this.parentScanner = parentScanner;
		this.target = target;
		executorService = Executors.newFixedThreadPool(1);
		executorCompletionService = new ExecutorCompletionService<Integer>(executorService);
//		pendingPlugin= new HashMap<>();
		activeConnections = new DualHashBidiMap();
		channelProxyMap = new HashMap<>();
		
	}
	
//	private HandshakeConfig getHandshakeConfig(){
////		if(handshakeConfig == null){
////
//////			handshakeConfig = HttpHandshakeBuilder.getHttpHandshakeRequestHeader();
////		}
//		return handshakeConfig;
//	}
	
	public ServerConnectionEstablisher getConnectionEstablisher() {
		if(connectionEstablisher == null){
			connectionEstablisher = new ServerConnectionEstablisher();
		}
		return connectionEstablisher;
	}
	
	public WebSocketProxy getActiveConnection(WebSocketActivePlugin plugin) throws IOException, RequestOutOfScopeException {
		WebSocketProxy result;
		if(activeConnections.containsKey(plugin.getCode())){
			result = (WebSocketProxy) activeConnections.get(plugin.getCode());
			if(!result.isConnected()){
				result = result.reEstablishConnection(result.getHandShakeConfig());
				
				
				
			}
		}else{
			result = getConnectionEstablisher().send(getHandshakeConfig());
		}
		if(result != null){
			activeConnections.put(plugin.getCode(),result);
			channelProxyMap.put(result.getChannelId(),result);
		}
		return result;
	}
	
	public HandshakeConfig getHandshakeConfig() {
		return handshakeConfig;
	}
	
	public void setHandshakeConfig(HandshakeConfig handshakeConfig){
		LOGGER.info("Handshake Config Seted");
		this.handshakeConfig = handshakeConfig;
		handshakeConfig.addChannelObserver(this);
	}
	
	private void recursiveScan(WebSocketTarget target){
		if(target.getStartingNode() == null){
			return;
		}
		
		if(!target.getStartingNode().getNodeType().isFolder()){
			scan(target);
		}
		if(target.getStartingNode().getChildren().size() > 0){
			Iterator<StructuralWebSocketNode> iterator = target.getStartingNode().getChildrenIterator();
			while (iterator.hasNext()){
				recursiveScan(new WebSocketTarget(iterator.next(),true));
			}
		}
		
	}
	
	private void scan(WebSocketTarget target){
		for(WebSocketActivePlugin plugin : parentScanner.getPluginFactory().getSuitablePlugin(target.getStartingNode().getNodeType())){
			LOGGER.info("Suitable Plugin: " + plugin.getName());
			if (parentScanner.getPluginFactory().getPendingPlugin().containsKey(plugin.getCode())){
				parentScanner.getPluginFactory().getPendingPlugin().get(plugin.getCode()).addTarget(target);
			}else{
				parentScanner.getPluginFactory().getPendingPlugin().put(plugin.getCode(),plugin);
				plugin.addTarget(target);
				plugin.setParent(this);
			}
		}
	}
	
	@Override
	public Integer call(){
		LOGGER.info("HostProcess Running");
		LOGGER.info("Plug In List Size: " + parentScanner.getPluginList().size());
		hostProcessStartTime = System.currentTimeMillis();
		
		if(target.isRecurse()){
			recursiveScan(target);
		
		}else{
			scan(target);
		}
		
		for(WebSocketActivePlugin plugin : parentScanner.getPluginFactory().getPendingPlugin().values()){
			LOGGER.info("A plugin Submited: " + plugin.getName());
			executorCompletionService.submit(plugin);
			
		}
		
		for (int i = 0; i < parentScanner.getPluginFactory().getPendingPlugin().size(); i++){
			try {
				executorCompletionService.take();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			LOGGER.info("A Plugin Finished");
		}
		
		return null;
	}
	
	@Override
	public int getObservingOrder() {
		return 0;
	}
	
	@Override
	public boolean onMessageFrame(int channelId, WebSocketMessage message) {
		WebSocketActivePlugin plugin = parentScanner.getPluginFactory().getPendingPlugin((int)activeConnections.getKey(channelProxyMap.get(channelId)));
		plugin.messageReceived(message.getDTO());
		return true;
	}
	
	@Override
	public void onStateChange(WebSocketProxy.State state, WebSocketProxy proxy) {
		LOGGER.info("ActiveConnectionL size: " + activeConnections.size());
		if(state != WebSocketProxy.State.CONNECTING && state != WebSocketProxy.State.OPEN) {
			WebSocketActivePlugin plugin = parentScanner.getPluginFactory().getPendingPlugin((int)activeConnections.getKey(proxy.getChannelId()));
			if(plugin != null) {
				LOGGER.info("Plugin Getted: " + plugin.getName());
				plugin.connectionStateChanged(state, proxy);
			}
		}

	}
}
