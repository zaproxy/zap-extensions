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

import javax.swing.ImageIcon;

import org.parosproxy.paros.model.SiteNode;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

public class MonitoredPage {

	private String id;
	private HttpMessage message;
	private SiteNode node = null;
	private Date lastMessage;
	
	public MonitoredPage(String id, HttpMessage message, Date lastMessage) {
		super();
		this.id = id;
		this.message = message;
		this.lastMessage = lastMessage;
	}
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public HttpMessage getMessage() {
		return message;
	}
	public void setMessage(HttpMessage message) {
		this.message = message;
	}
	public Date getLastMessage() {
		return lastMessage;
	}
	public void setLastMessage(Date lastMessage) {
		this.lastMessage = lastMessage;
	}
	public SiteNode getNode() {
		return node;
	}
	public void setNode(SiteNode node) {
		this.node = node;
	}
	public ImageIcon getIcon() {
		String userAgent = message.getRequestHeader().getHeader(HttpHeader.USER_AGENT);
		if (userAgent != null) {
			userAgent = userAgent.toLowerCase();
			if (userAgent.indexOf("firefox") >= 0) {
				return new ImageIcon(ExtensionPlugNHack.class.getResource(ExtensionPlugNHack.FIREFOX_ICON_RESOURCE));
			}
			if (userAgent.indexOf("chrome") >= 0) {
				return new ImageIcon(ExtensionPlugNHack.class.getResource(ExtensionPlugNHack.CHROME_ICON_RESOURCE));
			}
			if (userAgent.indexOf("msie") >= 0) {
				return new ImageIcon(ExtensionPlugNHack.class.getResource(ExtensionPlugNHack.IE_ICON_RESOURCE));
			}
			if (userAgent.indexOf("opera") >= 0) {
				return new ImageIcon(ExtensionPlugNHack.class.getResource(ExtensionPlugNHack.OPERA_ICON_RESOURCE));
			}
			if (userAgent.indexOf("safari") >= 0) {
				return new ImageIcon(ExtensionPlugNHack.class.getResource(ExtensionPlugNHack.SAFARI_ICON_RESOURCE));
			}
		}
		
		return null;
	}

	
}
