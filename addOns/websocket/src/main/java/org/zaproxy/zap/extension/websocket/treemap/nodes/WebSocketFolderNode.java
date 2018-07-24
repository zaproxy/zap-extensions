package org.zaproxy.zap.extension.websocket.treemap.nodes;

import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.extension.websocket.WebSocketChannelDTO;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;

import java.util.List;

public class WebSocketFolderNode extends WebSocketTreeNode {
    
    private static final long serialVersionUID = 2311091007687312333L;
    private List<HistoryReference> historyReferences;
    
    public WebSocketFolderNode(WebSocketNodeType type, String nodeName, StructuralWebSocketNode parent) {
        super(type,parent, nodeName);
    }
    
    static public WebSocketFolderNode getRootFolderNode(){
        return new WebSocketFolderNode(WebSocketNodeType.FOLDER_ROOT, Constant.messages.getString("websocket.treemap.close.root"), null);
    }
    
    static public WebSocketFolderNode getHandshakeFolderNode(WebSocketTreeNode parent){
        return new WebSocketFolderNode(WebSocketNodeType.FOLDER_HANDSHAKES, Constant.messages.getString("websocket.treemap.folder.handshakes"), parent);
    }
    
    static public WebSocketFolderNode getMessagesFolderNode(WebSocketTreeNode parent){
        return new WebSocketFolderNode(WebSocketNodeType.FOLDER_MESSAGES, Constant.messages.getString("websocket.treemap.folder.messages"), parent);
    }
    
    static public WebSocketFolderNode getHeartbeatsFolderNode(WebSocketTreeNode parent){
        return new WebSocketFolderNode(WebSocketNodeType.FOLDER_HEARTBEATS, Constant.messages.getString("websocket.treemap.folder.heartbeats"), parent);
    }
    
    static public  WebSocketFolderNode newFolderNode(WebSocketTreeNode parent, WebSocketNodeType type){
        return new WebSocketFolderNode(type,getConstantMessage(type),parent);
    }
    
    static private String getConstantMessage(WebSocketNodeType type){
        String message = null;
        switch (type){
            case FOLDER_MESSAGES:
                message = Constant.messages.getString("websocket.treemap.folder.messages");
                break;
            case FOLDER_CLOSE:
                message = Constant.messages.getString("websocket.treemap.folder.close");
                break;
            case FOLDER_HEARTBEATS:
                message = Constant.messages.getString("websocket.treemap.folder.heartbeats");
                break;
            case FOLDER_ROOT:
                message = Constant.messages.getString("websocket.treemap.folder.root");
                break;
        }
        return message;
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
    
    public void addInHistoryReferences(HistoryReference historyReference){
        historyReferences.add(historyReference);
    }
}
