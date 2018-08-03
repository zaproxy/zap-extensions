/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package org.zaproxy.zap.extension.websocket.client;

import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import fi.iki.elonen.NanoWSD;
import fi.iki.elonen.NanoWSD.WebSocketFrame;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertTrue;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.websocket.ExtensionWebSocket;
import org.zaproxy.zap.extension.websocket.WebSocketProxy;
import org.zaproxy.zap.testutils.WebSocketTestUtils;
import org.zaproxy.zap.testutils.websocket.server.NanoWebSocketConnection;

import java.util.List;
import java.util.Stack;

public class WebSocketProxyUnitTest extends WebSocketTestUtils {
	
	private final static String HOST_NAME = "localhost";
	
	@Before
	public void openWebSocketServer() throws Exception {
		super.startWebSocketServer(HOST_NAME);
		super.setUpZap();
	}
	
	@After
	@Override
	public void stopWebSocketServer(){
		super.stopWebSocketServer();
	}
	
	@Override
	protected void setUpMessages() {
		mockMessages(new ExtensionWebSocket());
	}
	
	@Test
	public void shouldAnswerToPingWithPong() throws Exception {
		ServerConnectionEstablisher establisher = new ServerConnectionEstablisher();
		HttpMessage handshakeRequest = new HttpMessage(HttpHandshakeBuilder.getHttpHandshakeRequestHeader(super.getServertUrl()));
		
		WebSocketProxy webSocketProxy = establisher.send(new HandshakeConfig(handshakeRequest,false,false));
		NanoWebSocketConnection webSocketConnection = super.getLastConnection();
		
		webSocketConnection.setPingScheduling(50,("1010").getBytes());
		
		Thread.sleep(300);
		
		assertTrue(webSocketProxy.isConnected());
		
		List<WebSocketFrame> messages = webSocketConnection.getListOfIncomingMessages();
		assertThat(messages, hasSize(greaterThanOrEqualTo(4)));
		
		for(WebSocketFrame message : messages){
			assertEquals("1010", message.getTextPayload());
			assertEquals("Pong", message.getOpCode().toString());
		}
		
	}
	
	@Test
	public void shouldReceiveMessagesFromServer() throws Exception {
		ServerConnectionEstablisher establisher = new ServerConnectionEstablisher ();
		HttpMessage handshakeRequest = new HttpMessage(HttpHandshakeBuilder.getHttpHandshakeRequestHeader(super.getServertUrl()));
		
		WebSocketProxy webSocketProxy = establisher.send(new HandshakeConfig(handshakeRequest,false,false));
		NanoWebSocketConnection webSocketConnection = super.getWebSocketTestServer().getLastConnection();
		
		Stack<NanoWSD.WebSocketFrame> webSocketFrameStack = new Stack<>();
		webSocketFrameStack.push(new NanoWSD.WebSocketFrame(WebSocketFrame.OpCode.Text,true,"Hello World"));
		webSocketFrameStack.push(new NanoWSD.WebSocketFrame(WebSocketFrame.OpCode.Text,true,"Hello World-2"));
		webSocketFrameStack.push(new NanoWSD.WebSocketFrame(WebSocketFrame.OpCode.Text,true,"Hello World-3"));
		webSocketConnection.setOutgoingMessageSchedule(webSocketFrameStack,50);
		
		Thread.sleep(200);
		assertEquals(4,webSocketProxy.getIncrementedMessageCount());
		
	}
	
}
