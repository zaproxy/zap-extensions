package org.zaproxy.zap.extension.websocket.treemap.nodes;

import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.treemap.analyzers.PayloadAnalyzer;
import org.zaproxy.zap.extension.websocket.treemap.analyzers.structures.PayloadStructure;
import org.zaproxy.zap.extension.websocket.utility.InvalidUtf8Exception;

import java.util.List;

public class WebSocketMessageNode extends WebSocketTreeNode{
    public static final int MAX_LENGTH = 40;
    private WebSocketMessageDTO messageDTO;
    private PayloadAnalyzer payloadAnalyzer = null;
	private PayloadStructure payloadStructure = null;
	
	public WebSocketMessageNode(WebSocketNodeType type, StructuralWebSocketNode parent, WebSocketMessageDTO webSocketMessage, String nodeName) throws Exception {
		super(type, parent, nodeName);
		messageDTO = webSocketMessage;
	}
	
	public void setPayloadAnalyzer(PayloadAnalyzer payloadAnalyzer) {
		this.payloadAnalyzer = payloadAnalyzer;
	}
	
	public void setPayloadStructure(PayloadStructure payloadStructure) {
		this.payloadStructure = payloadStructure;
	}
	
	@Override
    public WebSocketMessageDTO getWebSocketMessageDTO() {
        return messageDTO;
    }
    
    @Override
    public WebSocketChannelDTO getWebSocketChannelDTO() {
        return messageDTO.channel;
    }
    
    @Override
    public List<HistoryReference> getHandshakeMessage() {
        return parent.getHandshakeMessage();
    }
	
	@Override
	public void setNodeName(String nodeName) {
		this.nodeName = nodeName;
	}
	
	@Override
    public URI getURI() {
        return null;
    }
    
    @Override
    public boolean isDataDriven() {
        return false;
    }
    
}
