package org.zaproxy.zap.extension.websocket.treemap.nodes;

import org.apache.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;

public class WebSocketHandshakeNode  extends WebSocketTreeNode {
    
    private Logger LOGGER = Logger.getLogger(WebSocketHandshakeNode.class);
    
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
    public HistoryReference getHandshakeRef() {
        return handshakeReference;
    }
    
    public void addHandshakeRef(HistoryReference handshakeReference){
        this.handshakeReference = handshakeReference;
        try {
            LOGGER.info("New Handshake: " + handshakeReference.getHttpMessage().toString());
        } catch (HttpMalformedHeaderException e) {
            e.printStackTrace();
        } catch (DatabaseException e) {
            e.printStackTrace();
        }
    }
    
    @Override
    public boolean isConnected() {
        return false;
    }
    
    public void setHandshakeReference(HistoryReference handshakeReference) {
        this.handshakeReference = handshakeReference;
    }
    
    public HistoryReference getHandshakeReference() {
        return handshakeReference;
    }
}
