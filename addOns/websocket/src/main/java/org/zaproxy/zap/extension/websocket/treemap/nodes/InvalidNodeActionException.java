package org.zaproxy.zap.extension.websocket.treemap.nodes;

public class InvalidNodeActionException extends Exception {
	
	private static final long serialVersionUID = 9037903705930120525L;
	
	public InvalidNodeActionException(String message){
		super(message);
	}
}
