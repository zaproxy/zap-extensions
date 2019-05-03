package org.zaproxy.zap.extension.websocket.treemap;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.websocket.*;
import org.zaproxy.zap.extension.websocket.treemap.analyzers.LazyJsonAnalyzer;
import org.zaproxy.zap.extension.websocket.treemap.analyzers.AnalyzeManager;
import org.zaproxy.zap.extension.websocket.treemap.analyzers.PayloadAnalyzer;
import org.zaproxy.zap.extension.websocket.treemap.analyzers.structures.PayloadStructure;
import org.zaproxy.zap.extension.websocket.treemap.nodes.*;
import org.zaproxy.zap.extension.websocket.utility.InvalidUtf8Exception;
import org.zaproxy.zap.utils.Pair;

import java.util.Iterator;
import java.util.List;
import java.util.Stack;

//TODO: Add JavaDoc
public class WebSocketMap {
    private Logger LOGGER = Logger.getLogger(WebSocketMap.class);
    private WebSocketFolderNode root = null;
	private AnalyzeManager analyzeManager;
 
	private WebSocketMap(){
		analyzeManager = new AnalyzeManager();
		analyzeManager.addAnalyzer(new LazyJsonAnalyzer());
	}
	
	private WebSocketMapListener webSocketMapListener = null;
    
    public static WebSocketMap createTree(){
        WebSocketMap webSocketMap = new WebSocketMap();
        webSocketMap.setRoot(WebSocketFolderNode.getRootFolderNode());
        return webSocketMap;
    }
    
    public void setRoot(WebSocketFolderNode root){
        this.root = root;
    }
	
	//TODO: Add JavaDoc
    public WebSocketFolderNode getRoot(){
        if( root == null){
            root = WebSocketFolderNode.getRootFolderNode();
        }
        return root;
    }
	
	//TODO: Add JavaDoc
    public synchronized StructuralWebSocketNode addConnection(WebSocketProxy webSocketProxy){
        
        HttpMessage handshakeMessage;
        try{
            handshakeMessage = webSocketProxy.getHandshakeReference().getHttpMessage();
        } catch (Exception e) {
            LOGGER.error(e.getMessage(),e);
            return null;
        }
        URI uri = handshakeMessage.getRequestHeader().getURI();
        System.out.println(uri.toString());
        WebSocketTreeNode parent = getRoot();
        StructuralWebSocketNode result = null;
        try {
            String host = getWebSocketHostName(webSocketProxy.getDTO(), handshakeMessage);
            parent = findAndAddChild(parent, host, webSocketProxy, handshakeMessage); //If the Host haven't added yet, add them
            
            List<String> path = Model.getSingleton().getSession().getTreePath(handshakeMessage);
            result = addPath(parent, path); //If there is a path, add to the tree map Structure
            
        }catch (Exception e){
            LOGGER.error(e.getMessage(),e);
        }
		
        if(LOGGER.isDebugEnabled()){
			LOGGER.debug(toString());
		}
        return result;
    }
	
	//TODO: Add JavaDoc
    public synchronized StructuralWebSocketNode addMessage(WebSocketMessageDTO webSocketMessage){
        WebSocketChannelDTO webSocketChannel = webSocketMessage.channel;
        WebSocketTreeNode hostNode = null;
        try {
            hostNode = root.findChild(getWebSocketHostName(webSocketChannel,webSocketChannel.getHandshakeReference().getHttpMessage()));
        } catch (Exception e) {
			e.printStackTrace();
			return null;
		}
		WebSocketMessageNode result = null;
        if(hostNode != null){
            WebSocketTreeNode folderNode = getTypeFolder(hostNode,WebSocketNodeType.getAppropriateType(webSocketMessage.opcode,true));
            if(folderNode == null){
                folderNode = WebSocketFolderNode.newFolderNode(hostNode,WebSocketNodeType.getAppropriateType(webSocketMessage.opcode,true));
            }
			try {
				PayloadStructure payloadStructure = null;
				PayloadAnalyzer payloadAnalyzer = getAnalyzerForMessage(webSocketMessage);
				if(payloadAnalyzer != null ){
					try{
						payloadStructure = payloadAnalyzer.getPayloadStructure(webSocketMessage);
					}catch (Exception e){
						payloadStructure = null;
					}
				}
				result = new WebSocketMessageNode(WebSocketNodeType.getAppropriateType(webSocketMessage.opcode,false),folderNode,webSocketMessage, getNodeNameFromAnalyzer(payloadAnalyzer, payloadStructure, webSocketMessage));
			} catch (Exception e) {
				e.printStackTrace();
				return null;
			}
		}else{
        	//TODO: I should change that
            System.out.println("Something Went Wrong");
        }
        
        if(LOGGER.isDebugEnabled()){
			LOGGER.debug(toString());
		}
        return result;
    }
	
	static private String getNodeNameFromAnalyzer(PayloadAnalyzer payloadAnalyzer, PayloadStructure payloadStructure, WebSocketMessageDTO messageDTO){
		String nodeName;
		if(payloadAnalyzer != null){
			try {
				nodeName = payloadAnalyzer.getLeafName(payloadStructure);
			} catch (Exception e) {
				try {
					nodeName = messageDTO.getReadablePayload();
				} catch (InvalidUtf8Exception e1) {
					nodeName = Constant.messages.getString("websocket.payload.unreadable_binary");
				}
			}
		}else {
			try {
				nodeName = messageDTO.getReadablePayload();
			} catch (InvalidUtf8Exception e) {
				nodeName = Constant.messages.getString("websocket.payload.unreadable_binary");
			}
		}
		return nodeName;
	}
    
    private PayloadAnalyzer getAnalyzerForMessage(WebSocketMessageDTO message){
		return analyzeManager.recognizeMessage(message, null);
	}
    
    private WebSocketTreeNode getTypeFolder(WebSocketTreeNode hostNode, WebSocketNodeType type){
        return (WebSocketTreeNode) hostNode.getFirstTypeTopDown(type);
    }
    
    private WebSocketTreeNode addPath(WebSocketTreeNode parent, List<String> path){
        String folder;
        WebSocketTreeNode result = parent;
        WebSocketTreeNode parentChild;
        
        for (int i=0; i < path.size(); i++) {
            folder = path.get(i);
            if (folder != null && !folder.isEmpty()) {
                parentChild = result.findChild(folder);
                if(parentChild != null){
                    result = parentChild;
                }else if (i + 1 < path.size()){
                    result  = new WebSocketFolderNode(WebSocketNodeType.FOLDER_HANDSHAKES,folder,result);
                }else {
                    //TODO: Add the HistoryReference
                    result = new WebSocketHandshakeNode(result,folder,null);
                }
            }
        }
        return result;
    }
    
    public WebSocketTreeNode findAndAddChild(WebSocketTreeNode parent, String newNodeName, WebSocketProxy webSocketProxy, HttpMessage httpMessage) throws URIException, DatabaseException, HttpMalformedHeaderException {
        WebSocketTreeNode parentChild = parent.findChild(newNodeName);
        WebSocketTreeNode result = parentChild;
        
        if(parentChild == null && parent.isRoot()){ //This Handshake establish a new WebSocket connection
            result = createStructureForNewHost(parent, webSocketProxy, httpMessage, webSocketProxy.getHandshakeReference());
        }else if(parentChild.hasSameNodeName(newNodeName)){//Connection have been established (at least once)
            WebSocketTreeNode handshakeFolder = (WebSocketTreeNode) parentChild.getFirstTypeTopDown(WebSocketNodeType.FOLDER_HANDSHAKES);
            WebSocketTreeNode newParent = handshakeFolder.findChild(getHandshakeHostName(webSocketProxy.getHandshakeReference().getHttpMessage().getRequestHeader().getURI()));
            if(newParent != null){
                result = newParent;
            }else{
                //TODO: Add HistoryReference
                WebSocketHandshakeNode handshakeNode = new WebSocketHandshakeNode(handshakeFolder,newNodeName,null);
                handshakeFolder.addChild(handshakeNode);
                result = handshakeNode;
            }
        }
        return result;
    }
    
    private WebSocketTreeNode createStructureForNewHost(WebSocketTreeNode parent, WebSocketProxy webSocketProxy, HttpMessage handshakeMessage, HistoryReference historyReference) throws URIException {
        
        WebSocketFolderNode hostNode = new WebSocketFolderNode(WebSocketNodeType.FOLDER_HOST, getWebSocketHostName(webSocketProxy.getDTO(),handshakeMessage),parent);
        parent.addChild(hostNode);
        
        WebSocketFolderNode handshakeFolderNode = WebSocketFolderNode.getHandshakeFolderNode(parent);
        hostNode.addChild(handshakeFolderNode);
	
		//TODO: Maybe I should Add History Reference
        WebSocketHandshakeNode webSocketHandshakeNode = new WebSocketHandshakeNode(handshakeFolderNode, getHandshakeHostName( handshakeMessage.getRequestHeader().getURI()), historyReference);
        handshakeFolderNode.addChild(webSocketHandshakeNode);
        
        return webSocketHandshakeNode;
        
    }
    
    private String getWebSocketHostName(WebSocketChannelDTO webSocketChannelDTO, HttpMessage handshakeMessage) throws URIException {
        StringBuilder host = new StringBuilder();
        
        int port = webSocketChannelDTO.port != -1 ? webSocketChannelDTO.port : handshakeMessage.getRequestHeader().getURI().getPort();
        String scheme;
        if (port == 443 || handshakeMessage.getRequestHeader().isSecure()) {
            scheme = "wss";
        } else {
            scheme = "ws";
        }
        host.append(scheme).append("://").append(webSocketChannelDTO.host);
        
        if ((port != 80 && port != 443)) {
            host.append(":").append(port);
        }
    
        return host.toString();
    }
    
    private String getHandshakeHostName(URI uri) throws URIException {
        StringBuilder host = new StringBuilder();
        
        String scheme = uri.getScheme();
        if (scheme == null) {
            scheme = "http";
        } else {
            scheme = scheme.toLowerCase();
        }
        host.append(scheme).append("://").append(uri.getHost());
        
        int port = uri.getPort();
        if (port != -1 &&
                ((port == 80 && !"http".equals(scheme)) ||
                        (port == 443 && !"https".equals(scheme) ||
                                (port != 80 && port != 443)))) {
            host.append(":").append(port);
        }
        
        return host.toString();
    }
    
    public List<StructuralWebSocketNode> getAllHost(){
        return getRoot().getChildren();
    }
    
    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        int currentDepth;
        StructuralWebSocketNode currentNode;
        Pair<StructuralWebSocketNode,Integer> currentPair;
        Iterator<StructuralWebSocketNode> childrenIterator;
        Stack<Pair<StructuralWebSocketNode,Integer>> webSocketTreeNodeStack = new Stack<>();
        
        webSocketTreeNodeStack.push(new Pair<>(root,0));
        
        while ( !webSocketTreeNodeStack.empty()){ //Depth First
            currentPair = webSocketTreeNodeStack.pop();
            currentNode = currentPair.first;
            currentDepth = currentPair.second;
            
            for (int i = 0; i < currentDepth; i++){
                stringBuilder.append("\t");
            }
            
            stringBuilder.append("|- " + currentNode.getNodeName() + " (" + currentNode.getNodeType().toString()+ ")" + "\n");
            childrenIterator = currentNode.getChildrenIterator();
            while (childrenIterator.hasNext()){
                webSocketTreeNodeStack.push(new Pair<>(childrenIterator.next(),currentDepth+1));
            }
        }
        return stringBuilder.toString();
    }
	
	//TODO: Add JavaDoc
	public WebSocketMapListener getWebSocketMapListener() {
		if(webSocketMapListener == null){
			webSocketMapListener = new WebSocketMapListener();
		}
		return webSocketMapListener;
	}
	
	class WebSocketMapListener implements WebSocketObserver {
	
		private static final int OBSERVER_ORDER = 30;
		
		@Override
		public int getObservingOrder() {
			return OBSERVER_ORDER;
		}
	
		@Override
		public boolean onMessageFrame(int channelId, WebSocketMessage message) {
			addMessage(message.getDTO());
			return true;
		}
	
		@Override
		public void onStateChange(WebSocketProxy.State state, WebSocketProxy proxy) {
			if( state == WebSocketProxy.State.CONNECTING ){
				addConnection(proxy);
			}
		}
	}
}

