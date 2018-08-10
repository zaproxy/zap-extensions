package org.zaproxy.zap.extension.websocket.scanner.ascan.plugin.scripts;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;;
import org.zaproxy.zap.extension.websocket.client.RequestOutOfScopeException;
import org.zaproxy.zap.extension.websocket.scanner.ascan.plugin.WebSocketMessageNodeScan;
import org.zaproxy.zap.extension.websocket.scanner.ascan.plugin.scripts.interfaces.WebSocketActiveMessageScript;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketMessageNode;

import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.util.List;

public class ScriptWebSocketMessageActivePlugin extends WebSocketMessageNodeScan {
	
	private static final Logger LOGGER = Logger.getLogger(ScriptWebSocketMessageActivePlugin.class);
	public static final String PLUGIN_NAME = "WS.ScriptActiveScan";
	public static final int PLUGIN_ID = 1231223;
	
	private boolean isEnabled;
	private ExtensionScript extensionScript;
	
	@Override
	public void scanMessageNode(WebSocketMessageNode messageNode) {
		LOGGER.info("Scan Message: " + messageNode.getNodeName());
		if(getExtension() != null) {
			List<ScriptWrapper> scriptWrappers = extensionScript.getScripts(ExtensionWebSocket.SCRIPT_TYPE_WEBSOCKET_ACTIVE_MSG);
			for(ScriptWrapper scriptWrapper : scriptWrappers){
				if(scriptWrapper.isEnabled()){
					try{
						WebSocketActiveMessageScript script = extensionScript.getInterface(scriptWrapper, WebSocketActiveMessageScript.class);
						if(script != null){
							script.scan(messageNode, this);
						}else{
							extensionScript.handleFailedScriptInterface(
									scriptWrapper,
									Constant.messages.getString("websocket.pscan.scripts.interface.passive.error",
											scriptWrapper.getName())); //TODO CHANGE THE MESSAGE
						}
					} catch (Exception e) {
						extensionScript.handleScriptException(scriptWrapper,e);
					}
				}
			}
		}
	}
	
	private ExtensionScript getExtension() {
		if (extensionScript == null) {
			extensionScript = Control.getSingleton().getExtensionLoader().getExtension(ExtensionScript.class);
		}
		return extensionScript;
	}
	
	private boolean appliesToMessage(ScriptWrapper scriptWrapper, WebSocketActiveMessageScript script, WebSocketMessageNode webSocketMessageNode ){
		try {
			script.applyScan(webSocketMessageNode);
		}catch (UndeclaredThrowableException e) {
			// Python script implementation throws an exception if this optional/default method is not
			// actually implemented by the script (other script implementations, Zest/ECMAScript, just
			// use the default method).
			if (e.getCause() instanceof NoSuchMethodException && "applyScan".equals(e.getCause().getMessage())) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Script [Name=" + scriptWrapper.getName() + ", Engine=" + scriptWrapper.getEngineName()
							+ "]  does not implement the optional method applyScan: ", e);
				}
				return true;
			}
			throw e;
		}
		return true;
	}
	
	@Override
	public boolean applyScan(WebSocketMessageNode messageNode) {
		LOGGER.info("Apply scan to Message: " + messageNode.getNodeName());
		if(getExtension() != null){
			List<ScriptWrapper> scriptWrappers =
					extensionScript.getScripts(ExtensionWebSocket.SCRIPT_TYPE_WEBSOCKET_ACTIVE_MSG);
			for(ScriptWrapper scriptWrapper : scriptWrappers){
				if(scriptWrapper.isEnabled()){
					try {
						WebSocketActiveMessageScript script =
								extensionScript.getInterface(scriptWrapper, WebSocketActiveMessageScript.class);
						
						if(script != null){
							return appliesToMessage(scriptWrapper,script, messageNode);
						}else{
							extensionScript.handleFailedScriptInterface(
									scriptWrapper,
									Constant.messages.getString("websocket.pscan.scripts.interface.passive.error",
											scriptWrapper.getName()));//TODO CHANGE THE MESSAGE
						}
						
					} catch (Exception e) {
						extensionScript.handleScriptException(scriptWrapper,e);
					}
					
				}
			}
		}
		return false;
	}
	
	
	@Override
	public void messageReceived(WebSocketMessageDTO message) {
		if(getExtension() != null) {
			List<ScriptWrapper> scriptWrappers = extensionScript.getScripts(ExtensionWebSocket.SCRIPT_TYPE_WEBSOCKET_ACTIVE_MSG);
			for(ScriptWrapper scriptWrapper : scriptWrappers){
				if(scriptWrapper.isEnabled()){
					try{
						WebSocketActiveMessageScript script = extensionScript.getInterface(scriptWrapper, WebSocketActiveMessageScript.class);
						if(script != null){
							script.messageReceived(message);
						}else{
							extensionScript.handleFailedScriptInterface(
									scriptWrapper,
									Constant.messages.getString("websocket.pscan.scripts.interface.passive.error",
											scriptWrapper.getName())); //TODO CHANGE THE MESSAGE
						}
					} catch (Exception e) {
						extensionScript.handleScriptException(scriptWrapper,e);
					}
				}
			}
		}
	
	}
	
	private void connectionStateChanged(ScriptWrapper scriptWrapper, WebSocketActiveMessageScript script, WebSocketProxy.State state){
		try {
			script.connectionStateChanged(state);
		}catch (UndeclaredThrowableException e) {
			// Python script implementation throws an exception if this optional/default method is not
			// actually implemented by the script (other script implementations, Zest/ECMAScript, just
			// use the default method).
			if (e.getCause() instanceof NoSuchMethodException && "connectionStateChanged".equals(e.getCause().getMessage())) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Script [Name=" + scriptWrapper.getName() + ", Engine=" + scriptWrapper.getEngineName()
							+ "]  does not implement the optional method applyScan: ", e);
				}
			}
			throw e;
		}
	}
	
	@Override
	public void connectionStateChanged(WebSocketProxy.State state, WebSocketProxy proxy) {
		if(getExtension() != null){
			List<ScriptWrapper> scriptWrappers =
					extensionScript.getScripts(ExtensionWebSocket.SCRIPT_TYPE_WEBSOCKET_ACTIVE_MSG);
			for(ScriptWrapper scriptWrapper : scriptWrappers){
				if(scriptWrapper.isEnabled()){
					try {
						WebSocketActiveMessageScript script =
								extensionScript.getInterface(scriptWrapper, WebSocketActiveMessageScript.class);
						
						if(script != null){
							connectionStateChanged(scriptWrapper,script, state);
						}else{
							extensionScript.handleFailedScriptInterface(
									scriptWrapper,
									Constant.messages.getString("websocket.pscan.scripts.interface.passive.error",
											scriptWrapper.getName()));//TODO CHANGE THE MESSAGE
						}
						
					} catch (Exception e) {
						extensionScript.handleScriptException(scriptWrapper,e);
					}
					
				}
			}
		}
		
	}
	
	@Override
	public String getName() {
		return PLUGIN_NAME;
	}
	
	@Override
	public int getCode() {
		return PLUGIN_ID;
	}
	
	@Override
	public void sendMessage(WebSocketMessageDTO message) throws IOException, RequestOutOfScopeException {
		super.sendMessage(message);
	}
	
	
}
