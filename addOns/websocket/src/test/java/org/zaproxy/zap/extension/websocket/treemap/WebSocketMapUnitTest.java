package org.zaproxy.zap.extension.websocket.treemap;

import fi.iki.elonen.NanoWSD;
import org.apache.commons.httpclient.URI;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.websocket.*;
import org.zaproxy.zap.extension.websocket.client.HandshakeConfig;
import org.zaproxy.zap.extension.websocket.client.HttpHandshakeBuilder;
import org.zaproxy.zap.extension.websocket.client.ServerConnectionEstablisher;
import org.zaproxy.zap.extension.websocket.treemap.nodes.StructuralWebSocketNode;
import org.zaproxy.zap.extension.websocket.treemap.nodes.WebSocketTreeNode;
import org.zaproxy.zap.extension.websocket.utility.WebSocketUtils;
import org.zaproxy.zap.testutils.WebSocketTestUtils;
import org.zaproxy.zap.testutils.websocket.server.NanoWebSocketConnection;
import static org.mockito.Mockito.when;

import java.util.Iterator;
import java.util.List;
import java.util.Stack;

import static org.junit.Assert.assertEquals;

public class WebSocketMapUnitTest extends WebSocketTestUtils{
    WebSocketTreeNode webSocketTreeNode[][];
    
    @Before
    public void setUp() throws Exception {
        super.setUpZap();
        super.setUpLog();
        
        mockMessages(new ExtensionWebSocket());
    }
    
    @Override
    protected void setUpMessages() {
        mockMessages(new ExtensionWebSocket());
    }
    
    @Test
    public void insertNewWebSocketConnection() throws Exception {
        String hostname = "localhost";
        int port = 8885;
        super.startWebSocketServer(hostname,port);
        
        ServerConnectionEstablisher handshakeSender = new ServerConnectionEstablisher();
        HttpMessage handshakeRequest = new HttpMessage(HttpHandshakeBuilder.getHttpHandshakeRequestHeader(new URI("http://" + hostname + ":" + port,true)));

        WebSocketProxy webSocketProxy = handshakeSender.send(new HandshakeConfig(handshakeRequest,false,false));
        
        webSocketProxy.setHandshakeReference(getMockHistoryReference(handshakeRequest));
        
        assertEquals(101,handshakeRequest.getResponseHeader().getStatusCode());
        
        WebSocketMap webSocketMap = WebSocketMap.createTree();
        webSocketMap.addConnection(webSocketProxy);
        
        super.stopWebSocketServer();
    }
    
    @Test
    public void insertSomeHostConnection() throws Exception {
        String[] hostnames = new String[]{"www.example.com","www.example.com/first","www.example.com/first/first","www.example.com/first/second","www.example.com/second/first/first"};
        HttpMessage httpMessages;
        WebSocketProxy webSocketProxies;
        WebSocketMap webSocketMap = WebSocketMap.createTree();
        for(int i = 0; i < 5; i++){
            HttpRequestHeader httpRequestHeader = HttpHandshakeBuilder.getHttpHandshakeRequestHeader(new URI("http://" + hostnames[i] ,true));
            httpMessages = new HttpMessage(httpRequestHeader);
            httpMessages.setResponseHeader(getUpgradeRequestResponse(httpRequestHeader));
            webSocketProxies = getWebSocketProxyMock(httpMessages);
            webSocketMap.addConnection(webSocketProxies);
        }
        List<StructuralWebSocketNode> hostNodes = webSocketMap.getAllHost();
        
        Assert.assertEquals(webSocketMap.getRoot().getChildCount(),1);
        
        System.out.println(webSocketMap.toString());
    }
    
    @Test
    public void shouldAddMessage() throws Exception {
        String hostname = "http://www.example.com:80";
        WebSocketMap webSocketMap = WebSocketMap.createTree();
        
        HttpRequestHeader httpRequestHeader = HttpHandshakeBuilder.getHttpHandshakeRequestHeader(new URI(  hostname ,true));
        HttpMessage httpMessage = new HttpMessage(httpRequestHeader);
        httpMessage.setResponseHeader(getUpgradeRequestResponse(httpRequestHeader));
        
		HistoryReference historyReference = getMockHistoryReference(httpMessage);
        httpMessage.setHistoryRef(historyReference);
        
        WebSocketProxy webSocketProxy = getWebSocketProxyMock(httpMessage);
        webSocketMap.addConnection(webSocketProxy);
        
        WebSocketMessageDTO webSocketMessage = new WebSocketMessageDTO(webSocketProxy.getDTO());
        webSocketMessage.isOutgoing = true;
        webSocketMessage.payload = "Example Payload";
        webSocketMessage.opcode = WebSocketMessage.OPCODE_TEXT;
        webSocketMessage.channel = getWebSocketChannelMock(webSocketProxy.getHandshakeReference().getHttpMessage().getRequestHeader().getURI().toString(),
				 80, webSocketProxy.getHandshakeReference().getHttpMessage().getRequestHeader().getHostName(),
				historyReference);
        
        webSocketMap.addMessage(webSocketMessage);
        
        StructuralWebSocketNode hostNode = webSocketMap.getAllHost().get(0);
        Assert.assertEquals("ws://www.example.com",hostNode.getNodeName());
        Iterator<StructuralWebSocketNode> iterator = hostNode.getChildrenIterator();
        while (iterator.hasNext()) {
			StructuralWebSocketNode folder = iterator.next();
			if (folder.getNodeName().equals("Messages")) {
				Assert.assertEquals(webSocketMessage.payload, folder.getChildAt(0).getNodeName());
				break;
			}
		}
    }
    
//    @Test
//    public void shouldAddOnAppropriateFolder() throws Exception {
//        String hostname = "localhost";
//        final String MESSAGE = "Message: ";
//        final String CLOSE = " Close";
//        final String PING_STR = "101";
//        final byte[] PING = PING_STR.getBytes();
//
//        int port = 8885;
//        super.startWebSocketServer(hostname,port);
//
//		ServerConnectionEstablisher handshakeSender = new ServerConnectionEstablisher();
//        HttpMessage handshakeRequest = new HttpMessage(HttpHandshakeBuilder.getHttpHandshakeRequestHeader(new URI("http://" + hostname + ":" + port,true)));
//        WebSocketMap webSocketMap = WebSocketMap.createTree();
//
//        WebSocketProxy webSocketProxy = handshakeSender.send(new HandshakeConfig(handshakeRequest,false,false));
//        webSocketProxy.setHandshakeReference(super.getMockHistoryReference(handshakeRequest));
//        webSocketMap.addConnection(webSocketProxy);
//
//        webSocketProxy.addObserver(new WebSocketObserver() {
//            @Override
//            public int getObservingOrder() {
//                return 0;
//            }
//
//            @Override
//            public boolean onMessageFrame(int channelId, WebSocketMessage message) {
//            	WebSocketMessageDTO webSocketMessage = message.getDTO();
//				try {
//					webSocketMessage.channel = getWebSocketChannelMock(handshakeRequest.getRequestHeader().getURI().toString(),
//							handshakeRequest.getRequestHeader().getHostPort(),handshakeRequest.getRequestHeader().getHostName(),getMockHistoryReference(handshakeRequest));
//				} catch (DatabaseException e) {
//					e.printStackTrace();
//				} catch (HttpMalformedHeaderException e) {
//					e.printStackTrace();
//				}
//				webSocketMap.addMessage(webSocketMessage);
//                return false;
//            }
//
//            @Override
//            public void onStateChange(WebSocketProxy.State state, WebSocketProxy proxy) {
//
//            }
//        });
//        NanoWebSocketConnection webSocketConnection = getLastConnection();
//        webSocketConnection.setPingScheduling(100, PING);
//        Thread.sleep(150);
//        Stack<NanoWSD.WebSocketFrame> messages = new Stack<>();
//        for(int i = 0; i < 5; i++){
//            messages.push(new NanoWSD.WebSocketFrame(NanoWSD.WebSocketFrame.OpCode.Text,true,(MESSAGE + i).getBytes()));
//        }
//        webSocketConnection.setOutgoingMessageSchedule(messages,230);
//
//        Thread.sleep(10000);
//        webSocketConnection.close(NanoWSD.WebSocketFrame.CloseCode.GoingAway,CLOSE,true);
//        Thread.sleep(100);
//        webSocketMap.toString();
//
//        WebSocketTreeNode hostNode = (WebSocketTreeNode) webSocketMap.getAllHost().get(0);
//        Iterator<StructuralWebSocketNode> hostChildrenIterator = hostNode.getChildrenIterator();
//
//        WebSocketTreeNode currentNode;
//        while (hostChildrenIterator.hasNext()){
//            currentNode = (WebSocketTreeNode) hostChildrenIterator.next();
//            if(currentNode.getNodeName().equals("Close")){
//                Assert.assertEquals("1001"+CLOSE, currentNode.getChildAt(0).getNodeName());
//            }else if (currentNode.getNodeName().equals("Messages")){
//                List<StructuralWebSocketNode> messageNodes = currentNode.getChildren();
//                for(int i = 0; i < messageNodes.size(); i++){
//                    Assert.assertEquals(MESSAGE + (4 - i),messageNodes.get(i).getNodeName());
//                }
//            }else if(currentNode.getNodeName().equals("Heartbeats")){
//                Assert.assertEquals(PING_STR,currentNode.getChildAt(0).getNodeName());
//            }
//        }
//    }
	
	public HttpResponseHeader getUpgradeRequestResponse(HttpRequestHeader httpRequest){
		HttpResponseHeader httpResponse = new HttpResponseHeader();
		httpResponse.setVersion(HttpResponseHeader.HTTP11);
		httpResponse.setStatusCode(101);
		httpResponse.setHeader(HttpHandshakeBuilder.UPGRADE_HEADER,HttpHandshakeBuilder.UPGRADE_PARAMETER);
		httpResponse.setHeader(HttpHandshakeBuilder.CONNECTION,HttpHandshakeBuilder.CONNECTION_UPGRADE_PARAMETER);
		httpResponse.setHeader(HttpHandshakeBuilder.SEC_WEB_SOCKET_ACCEPT, WebSocketUtils.encodeWebSocketKey(httpRequest.getHeader(HttpHandshakeBuilder.SEC_WEB_SOCKET_KEY)));
		return httpResponse;
	}
	
	public WebSocketProxy getWebSocketProxyMock(HttpMessage handshakeMessage) throws DatabaseException, HttpMalformedHeaderException {
		WebSocketProxy webSocketProxy = Mockito.mock(WebSocketProxy.class);
		HistoryReference historyReference =  getMockHistoryReference(handshakeMessage);
		webSocketProxy.setHandshakeReference(historyReference);
		
		when(webSocketProxy.getHandshakeReference()).thenAnswer( (Answer<HistoryReference>) invocationOnMock -> historyReference);
		
		WebSocketChannelDTO webSocketChannelDTO = getWebSocketChannelMock(handshakeMessage.getRequestHeader().getURI().toString(), handshakeMessage.getRequestHeader().getURI().getPort()
				, handshakeMessage.getRequestHeader().getHostName(), historyReference);
		
		when(webSocketProxy.getDTO()).thenAnswer((Answer<WebSocketChannelDTO> ) invocationOnMock -> webSocketChannelDTO);
		return webSocketProxy;
	}
	
	public WebSocketChannelDTO getWebSocketChannelMock(final String url,final int port, final String host, final HistoryReference historyReference){
		WebSocketChannelDTO webSocketChannel = Mockito.mock(WebSocketChannelDTO.class);
		webSocketChannel.url = url;
		webSocketChannel.port = port;
		webSocketChannel.host = host;
		when(webSocketChannel.getHandshakeReference()).thenAnswer( (Answer<HistoryReference>) invocationOnMock -> historyReference);
		return webSocketChannel;
	}
	
	
	
	
	
}
