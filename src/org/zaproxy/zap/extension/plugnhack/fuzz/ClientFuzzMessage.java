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
package org.zaproxy.zap.extension.plugnhack.fuzz;

import net.sf.json.JSONObject;

import org.zaproxy.zap.extension.plugnhack.ClientMessage;

/**
 * Contains more information about fuzzing process.
 */
public class ClientFuzzMessage extends ClientMessage {

    public enum State {
    	PENDING,
        SUCCESSFUL,
        ERROR
    }

    /**
     * Id of fuzzing process.
     */
	public Integer fuzzId;
    
    /**
     * Contains sending status.
     */
    public State state = State.PENDING;
    
    /**
     * Text which was used for fuzzing.
     */
    public String fuzz;
	
	public ClientFuzzMessage(String clientId, JSONObject json) {
		super (clientId, json);
	}
}