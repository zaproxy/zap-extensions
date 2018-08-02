package org.zaproxy.zap.extension.websocket.treemap.nodes;

import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessage;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.treemap.analyzers.PayloadAnalyzer;
import org.zaproxy.zap.extension.websocket.treemap.analyzers.structures.PayloadStructure;
import org.zaproxy.zap.extension.websocket.utility.InvalidUtf8Exception;

import java.util.List;
import java.util.Objects;

public class WebSocketMessageNode extends WebSocketTreeNode{
	
	private Logger LOGGER = Logger.getLogger(WebSocketMessageNode.class);
	
    public static final int MAX_LENGTH = 40;
    
    private WebSocketMessageDTO messageDTO;
    private PayloadAnalyzer payloadAnalyzer = null;
	private PayloadStructure payloadStructure = null;
	
	public WebSocketMessageNode(WebSocketNodeType type, StructuralWebSocketNode parent, WebSocketMessageDTO webSocketMessage, String nodeName){
		super(type, parent, nodeName);
		messageDTO = webSocketMessage;
	}
	
	public void setPayloadAnalyzer(PayloadAnalyzer payloadAnalyzer) {
		this.payloadAnalyzer = payloadAnalyzer;
	}
	
	public void setPayloadStructure(PayloadStructure payloadStructure) {
		this.payloadStructure = payloadStructure;
	}
	
	public PayloadAnalyzer getPayloadAnalyzer() {
		return payloadAnalyzer;
	}
	
	public PayloadStructure getPayloadStructure() {
		return payloadStructure;
	}
	
	@Override
    public WebSocketMessageDTO getWebSocketMessageDTO() {
        return messageDTO;
    }
	
	@Override
	public HistoryReference getHandshakeRef() throws InvalidNodeActionException {
		
		WebSocketTreeNode handshakeNode  = (WebSocketTreeNode) this.getFirstTypeBottomUp(WebSocketNodeType.FOLDER_HOST)
				.getFirstTypeTopDown(WebSocketNodeType.FOLDER_HANDSHAKES)
				.getFirstTypeTopDown(WebSocketNodeType.HANDSHAKE);
		if(handshakeNode == null){
			throw new InvalidNodeActionException("I can't find HandshakeNode");
		}
		return handshakeNode.getHandshakeRef();
	}
	
	@Override
	public boolean isConnected() {
		return false;
	}
	
	@Override
	public boolean equals(Object object) {
		boolean result = false;
		
		if(object != null && object instanceof WebSocketMessageNode){
			WebSocketMessageNode webSocketMessageNode = (WebSocketMessageNode) object;
			WebSocketMessageDTO message = webSocketMessageNode.getWebSocketMessageDTO();
			result = (webSocketMessageNode.getNodeName().equals(nodeName)
					&& message.opcode.equals(this.messageDTO.opcode)
					&& message.isOutgoing == this.messageDTO.isOutgoing);
		}
		return result;
	}
	
	@Override
	public int hashCode() {
		int k1 = messageDTO.id;
		int k2 = messageDTO.channel.id;
		return 1/2*(k1+k2)*(k1+k2+1)+k2; //Cantor pairing function
	}
}
