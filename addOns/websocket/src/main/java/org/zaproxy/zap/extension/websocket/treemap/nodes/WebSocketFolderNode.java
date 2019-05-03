package org.zaproxy.zap.extension.websocket.treemap.nodes;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;


public class WebSocketFolderNode extends WebSocketTreeNode {
	
	private Logger LOGGER = Logger.getLogger(WebSocketFolderNode.class);
	
    private HashMap<Integer, WebSocketProxy> connectionMap;
    
    public WebSocketFolderNode(WebSocketNodeType type, String nodeName, StructuralWebSocketNode parent) {
        super(type,parent, nodeName);
    }
    
    static public WebSocketFolderNode getRootFolderNode(){
        WebSocketFolderNode root = new WebSocketFolderNode(WebSocketNodeType.FOLDER_ROOT, Constant.messages.getString("websocket.treemap.close.root"), null);
        root.setNodeIndex(new int[]{0});
        return root;
    }
    
    static public WebSocketFolderNode getHostFolderNode(String nodeName, StructuralWebSocketNode parent, WebSocketProxy webSocketProxy){
        WebSocketFolderNode hostNode = new WebSocketFolderNode(WebSocketNodeType.FOLDER_HOST, nodeName, parent);
        hostNode.addChannel(webSocketProxy);
        return hostNode;
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
    
    public void addChannel(WebSocketProxy webSocketProxy) {
        if(connectionMap == null){
            connectionMap = new HashMap<>();
        }
        connectionMap.put(webSocketProxy.getChannelId(), webSocketProxy);
    }
    
    @Override
    public WebSocketMessageDTO getWebSocketMessageDTO() {
        return null;
    }
    
    @Override
    public HistoryReference getHandshakeRef() throws InvalidNodeActionException {
        WebSocketTreeNode handshakeNode;
        if(this.type == WebSocketNodeType.FOLDER_ROOT){
            throw new InvalidNodeActionException("This is a root node, can not return handshake");
        }else if (this.type == WebSocketNodeType.FOLDER_HOST){
            handshakeNode = (WebSocketTreeNode) this.getFirstTypeTopDown(WebSocketNodeType.HANDSHAKE);
        }else{
            handshakeNode = (WebSocketTreeNode) this.getFirstTypeSibling(WebSocketNodeType.FOLDER_HANDSHAKES).getFirstTypeTopDown(WebSocketNodeType.HANDSHAKE);
        }
        if(handshakeNode == null){
            throw new InvalidNodeActionException("I can't find HandshakeNode");
        }
        return handshakeNode.getHandshakeRef();
    }
    
    @Override
    public boolean isConnected() {
        if(connectionMap != null){
            Iterator<Map.Entry<Integer, WebSocketProxy>> iterator = connectionMap.entrySet().iterator();
            while(iterator.hasNext()){
                if(iterator.next().getValue().isConnected()){
                    return true;
                }
            }
    
        }
        return false;
	}
}
