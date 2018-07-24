package org.zaproxy.zap.extension.websocket.treemap.nodes;

import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;

import java.util.List;

public class WebSocketHandshakeNode  extends WebSocketTreeNode {
    private HistoryReference handshakeReference;
    
    public WebSocketHandshakeNode(StructuralWebSocketNode parent, String nodeName, HistoryReference handshakeReference) {
        super(WebSocketNodeType.HANDSHAKE, parent, nodeName);
        this.handshakeReference = handshakeReference;
    }
    
    @Override
    public WebSocketMessageDTO getWebSocketMessageDTO() {
        return null;
    }
    
    @Override
    public WebSocketChannelDTO getWebSocketChannelDTO() {
        return null;
    }
    
    @Override
    public List<HistoryReference> getHandshakeMessage() {
        return null;
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
    
    public void setHandshakeReference(HistoryReference handshakeReference) {
        this.handshakeReference = handshakeReference;
    }
    
    public HistoryReference getHandshakeReference() {
        return handshakeReference;
    }
}
