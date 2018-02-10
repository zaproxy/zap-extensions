/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.viewstate.zap.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;

import org.apache.log4j.Logger;

public class ViewState {
        
	private static Logger logger = Logger.getLogger(ViewState.class);
	
	private String type;
	protected String value;
	protected String name;
	
	public ViewState(String val, String type, String name) {
		this.value = val;
		this.type = type;
		this.name = name;
	}
	
	public String getType() {
		return this.type;
	}
	
	public String getValue() {
		return this.value;
	}
	
	public String getName() {
		return this.name;
	}
	
	public byte[] getDecodedValue() {
		byte[] val = null;
		try {
			if (getType().equalsIgnoreCase(ASPViewState.KEY)) {
				ASPViewState avs = (ASPViewState) this;
				val = avs.decode();
			}
			if (getType().equalsIgnoreCase(JSFViewState.KEY)) {
				JSFViewState jvs = (JSFViewState) this;
				ByteArrayOutputStream b = new ByteArrayOutputStream();
				ObjectOutputStream o = new ObjectOutputStream(b);
				o.writeObject(jvs.decode());
				val = b.toString().getBytes();
			}
		} catch (Exception e) {
			logger.error("Exception in getDecodedValue(): " + e.getMessage(), e);
		}
		return val;
	}
	
	public String getEncodedValue(byte[] plain) {
		String val = null;
		try {
			if (getType().equalsIgnoreCase(ASPViewState.KEY)) {
				ASPViewState avs = (ASPViewState) this;
				val = avs.encode(plain);
			}
			if (getType().equalsIgnoreCase(JSFViewState.KEY)) {
				JSFViewState jvs = (JSFViewState) this;
				val = jvs.encode(plain);
			}
		} catch (Exception e) {
			logger.error("Exception in getEncodedValue(): " + e.getMessage(), e);
		}
		return val;
	}
        
}
