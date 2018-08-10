package org.zaproxy.zap.extension.websocket.scanner.ascan;

import org.apache.log4j.Logger;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.websocket.client.HandshakeConfig;
import org.zaproxy.zap.extension.websocket.scanner.ascan.plugin.WebSocketActivePlugin;
import org.zaproxy.zap.extension.websocket.treemap.nodes.StructuralWebSocketNode;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.Executors;

public class WebSocketScanner implements Runnable{

	private static Logger LOGGER = Logger.getLogger(WebSocketScanner.class);
	
	public final static  int DEFAULT_THREAD_NUM = 1;
	
	private Executor executorService;
	private ExecutorCompletionService<Integer> executorCompletionService;
	private volatile boolean isRunning = false;
	private WebSocketTarget target = null;
	private List<WebSocketHostProcess> hostProcesses = new ArrayList<>();
	private WebSocketActiveScanManager activeScanManager;
	
	
	public WebSocketScanner(WebSocketActiveScanManager webSocketActiveScanManager) {
		this.activeScanManager = webSocketActiveScanManager;
		executorService = Executors.newFixedThreadPool(DEFAULT_THREAD_NUM);
		executorCompletionService = new ExecutorCompletionService<Integer>(executorService);
	}
	
	public void reset(){
		hostProcesses.clear();
	}
	
	public boolean isRunning() {
		return isRunning;
	}
	
	public void setTarget(WebSocketTarget target){
		this.target = target;
	}
	
	public Collection<WebSocketActivePlugin> getPluginList(){
		return activeScanManager.getWebSocketPluginFactory().getPluginList();
	}
	
	public WebSocketPluginFactory getPluginFactory(){
		return activeScanManager.getWebSocketPluginFactory();
	}
	
	
	@Override
	public void run() {
		getPluginFactory().reset();
		isRunning = true;
		try {
			LOGGER.info("WebSocket Active Scanner Running...");
			scan(target);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		isRunning = false;
	}
	
	public void scan(WebSocketTarget target) throws InterruptedException{
		if(target.getStartingNode() != null){
			if(target.getStartingNode().isRoot()){
				LOGGER.info("Scanner root");
				List<StructuralWebSocketNode> hosts = target.getStartingNode().getChildren();
				for(StructuralWebSocketNode host : hosts){
					LOGGER.info("Scan for host: " + host.getNodeName());
					WebSocketTarget hostTarget = new WebSocketTarget(host, target.isRecurse());
					WebSocketHostProcess hostProcess = new WebSocketHostProcess(this, hostTarget);
					
					HttpMessage handshakeMessage;
					try {
						HistoryReference historyReference = host.getHandshakeRef();
						if(historyReference == null){
							throw new Exception("I can't find the history reference");
						}
						handshakeMessage = historyReference.getHttpMessage();
					} catch (Exception e) {
						e.printStackTrace();
						return;
					}
					hostProcess.setHandshakeConfig(new HandshakeConfig(handshakeMessage));
					LOGGER.info("Ready to submit");
					executorCompletionService.submit(hostProcess);
				}
				
			}else{
				LOGGER.info("Scanner not root");
				WebSocketHostProcess hostProcess = new WebSocketHostProcess(this,target);
				
				HttpMessage handshakeMessage;
				try {
					HistoryReference historyReference = target.getStartingNode().getHandshakeRef();
					if(historyReference == null){
						throw new Exception("I can't find the history reference");
					}
					handshakeMessage = historyReference.getHttpMessage();
				} catch (Exception e) {
					e.printStackTrace();
					return;
				}
				hostProcess.setHandshakeConfig(new HandshakeConfig(handshakeMessage));
				LOGGER.info("Ready to submit");
				executorCompletionService.submit(hostProcess);
			}
		}
		for (int i = 0; i < hostProcesses.size(); i++){
			executorCompletionService.take();
			LOGGER.info("A host Proccess Finished");
		}
		
		getPluginFactory().reset();
	}
}
