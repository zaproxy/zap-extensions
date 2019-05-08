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
package org.zaproxy.zap.extension.websocket.ui.httppanel.models;

import java.util.Arrays;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.websocket.WebSocketMessage;
import org.zaproxy.zap.extension.websocket.utility.InvalidUtf8Exception;

public class StringWebSocketPanelViewModel extends AbstractWebSocketStringPanelViewModel {
	
	private static final Logger LOGGER = Logger.getLogger(StringWebSocketPanelViewModel.class);
	private boolean isErrorMessage;
	private boolean editable;
    
    @Override
    public String getData() {
        String data;
        if (webSocketMessage == null || webSocketMessage.payload == null)  {
            data = "";
        }else if(editable){
            try {
                data = webSocketMessage.getReadablePayload();
                isErrorMessage = false;
            } catch (InvalidUtf8Exception e) {
                isErrorMessage = true;
                if (webSocketMessage.opcode.equals(WebSocketMessage.OPCODE_BINARY)) {
                    data = Constant.messages.getString("websocket.payload.unreadable_binary");
                } else {
                    data = Constant.messages.getString("websocket.payload.invalid_utf8");
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("Unable to decode " + Arrays.toString((byte[]) webSocketMessage.payload) + " as UTF-8.", e);
                    }
                }
            }
        }else {
            data = webSocketMessage.getPayloadAsString();
        }
        return data;
    }

    @Override
    public void setData(String data) {
		if(isErrorMessage &&
				((webSocketMessage.opcode.equals(WebSocketMessage.OPCODE_BINARY)
						&& data.equals(Constant.messages.getString("websocket.payload.unreadable_binary")))
				||webSocketMessage.opcode.equals(WebSocketMessage.OPCODE_TEXT)
						&& data.equals(Constant.messages.getString("websocket.payload.invalid_utf8")))){
			//do not set data if it is an error message and has not been modified
			return;
		}
    	if (webSocketMessage.opcode != null) {
			if (webSocketMessage.opcode == WebSocketMessage.OPCODE_BINARY) {
				webSocketMessage.payload = data.getBytes();
			} else {
				webSocketMessage.payload = data;
			}
		} else {
			if (webSocketMessage.payload instanceof String) {
				webSocketMessage.payload = data;
			} else if (webSocketMessage.payload instanceof byte[]) {
				webSocketMessage.payload = data.getBytes();
			}
		}
    }
    
	public void setEditable(boolean editableMessage) {
		editable = editableMessage;
		if(editableMessage){
			fireDataChanged();
		}
	}
}
