/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.plugnhack.httppanel.views;

import org.zaproxy.zap.extension.httppanel.view.FuzzableMessage;
import org.zaproxy.zap.extension.plugnhack.ClientMessage;
import org.zaproxy.zap.extension.plugnhack.fuzz.ClientFuzzMessage;

/**
 * Is called for example from the Request/Response tab, when fuzzing is chosen.
 * It takes a {@link ClientMessage} and is able to fuzz it with given
 * strings. Finally a {@link ClientFuzzMessage} is returned.
 */
public class ClientFuzzableTextMessage implements FuzzableMessage {

	public enum Location {HEADER, BODY};
	
	private final ClientMessage message;
	private final int start;
	private final int end;
	
	public ClientFuzzableTextMessage(ClientMessage message, int start, int end) {
		this.message = message;
		
		this.start = start;
		this.end = end;
	}
	
	@Override
	public ClientMessage getMessage() {
		return message;
	}

	@Override
	public ClientFuzzMessage fuzz(String fuzzString) throws IllegalArgumentException {
		ClientFuzzMessage fuzzedMessage = copyMessage(message);

		String orig = fuzzedMessage.getData();
		
		final int length = orig.length();
		StringBuilder sb = new StringBuilder(start + fuzzString.length() + length - end);
		
		sb.append(orig.substring(0, start));
		sb.append(fuzzString);
		sb.append(orig.substring(end));
		
		fuzzedMessage.setData(sb.toString());
		return fuzzedMessage;
	}
	
	/**
	 * Helper to duplicate the message.
	 * 
	 * @param msg
	 * @return
	 */
	private ClientFuzzMessage copyMessage(ClientMessage msg) {
        return new ClientFuzzMessage(msg.getClientId(), msg.getJson());
	}
}
