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
package org.zaproxy.zap.extension.plugnhack;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.zaproxy.zap.extension.httppanel.Message;

import net.sf.json.JSONObject;

public class ClientMessage implements Message {

	public enum State {received, pending, resent, dropped}
	private JSONObject json;
	private String clientId;
	private Date received;
	private String from;
	private String to;
	private String type;
	private String data;
	private String target;
	private String messageId;
	private String endpointId;
	private State state = State.received;
	private boolean changed = false;

	public ClientMessage(String clientId, JSONObject json) {
		super();
		setReceived(new Date());
		this.clientId = clientId;
		// Copy the full json structure, otherwise can be affected by 'external' changes
		this.setJson(JSONObject.fromObject(json.toString()));
	}
	
	public void setJson(JSONObject json) {
		this.json = json;
		if (json.has("type")) {
			setType(json.getString("type"));
		}
		if (json.has("from")) {
			setFrom(json.getString("from"));
		}
		if (json.has("to")) {
			setTo(json.getString("to"));
		}
		if (json.has("target")) {
			setTarget(json.getString("target"));
		}
		if (json.has("data")) {
			setData(json.getString("data"));
		}
		if (json.has("messageId")) {
			setMessageId(json.getString("messageId"));
		}
		if (json.has("endpointId")) {
			setEndpointId(json.getString("endpointId"));
		}
		
	}

	public Date getReceived() {
		return received;
	}
	public void setReceived(Date received) {
		this.received = received;
	}
	public String getFrom() {
		return from;
	}
	public void setFrom(String from) {
		this.from = from;
		this.json.put("from", from);
	}
	public String getTo() {
		return to;
	}
	public void setTo(String to) {
		this.to = to;
		this.json.put("to", to);
	}
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
		this.json.put("type", type);
	}
	public String getData() {
		return data;
	}
	public void setData(String data) {
		this.data = data;
		this.json.put("data", data);
	}
	public String getEndpointId() {
		return endpointId;
	}
	public void setEndpointId(String endpointId) {
		this.endpointId = endpointId;
	}

	public Map<String, String> toMap() {
		HashMap<String, String> map = new HashMap<String, String>();
		if (this.to != null) {
			map.put("to", this.to);
		}
		if (this.from != null) {
			map.put("from", this.from);
		}
		if (this.type != null) {
			map.put("type", this.type);
		}
		if (this.target != null) {
			map.put("target", this.target);
		}
		if (this.data != null) {
			map.put("data", this.data);
		}
		if (this.messageId != null) {
			map.put("messageId", this.messageId);
		}
		if (this.endpointId != null) {
			map.put("endpointId", this.endpointId);
		}
		return map;
	}

	public String getTarget() {
		return target;
	}

	public void setTarget(String target) {
		this.target = target;
		this.json.put("target", target);
	}

	public String getMessageId() {
		return messageId;
	}

	public void setMessageId(String messageId) {
		this.messageId = messageId;
		this.json.put("messageId", messageId);
	}

	public JSONObject getJson() {
		return json;
	}

	public String getClientId() {
		return clientId;
	}

	@Override
	public boolean isInScope() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isForceIntercept() {
		// TODO Auto-generated method stub
		return false;
	}

	public boolean isChanged() {
		return changed;
	}

	public void setChanged(boolean changed) {
		this.changed = changed;
	}

	public State getState() {
		return state;
	}

	public void setState(State state) {
		this.state = state;
	}
	
}
