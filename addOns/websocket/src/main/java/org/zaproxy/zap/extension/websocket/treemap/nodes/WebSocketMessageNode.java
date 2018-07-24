package org.zaproxy.zap.extension.websocket.treemap.nodes;

import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessage;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.utility.InvalidUtf8Exception;

import java.util.List;

public class WebSocketMessageNode extends WebSocketTreeNode{
    public static final int MAX_LENGTH = 40;
    private WebSocketMessageDTO messageDTO;
    
    public WebSocketMessageNode(WebSocketNodeType type, StructuralWebSocketNode parent, WebSocketMessageDTO webSocketMessage) throws InvalidUtf8Exception {
        super(type, parent, webSocketMessage.getReadablePayload().length() < MAX_LENGTH ? webSocketMessage.getReadablePayload() : webSocketMessage.getReadablePayload().substring(MAX_LENGTH));
        messageDTO = webSocketMessage;
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
    public URI getURI() {
        return null;
    }
    
    @Override
    public boolean isDataDriven() {
        return false;
    }
    
}
