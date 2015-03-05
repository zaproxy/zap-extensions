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
package org.zaproxy.zap.extension.pscanrulesBeta;

import java.util.List;

import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import net.htmlparser.jericho.StartTag;
import net.htmlparser.jericho.StartTagType;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * A port from a Watcher passive scanner (http://websecuritytool.codeplex.com/)
 * rule {@code CasabaSecurity.Web.Watcher.Checks.CheckPasvCharsetMismatch}
 */
public class CharsetMismatchScanner extends PluginPassiveScanner {

	private PassiveScanThread parent = null;

	/**
	 * Prefix for internationalized messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanbeta.charsetmismatch.";

	@Override
	public String getName() {
		return Constant.messages.getString(MESSAGE_PREFIX + "name");
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// do nothing
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		if (msg.getResponseBody().length() == 0) {
			return;
		}
		
		// Charset specified in the Content-Type header
		String headerCharset = msg.getResponseHeader().getCharset();
		
 		// TODO: If Content-Type in the Header doesn't specify a charset, or
		// the Content-Type header is missing - should we raise some different 
		// alert? Ignore such case for now.
		if (headerCharset == null) {
			return;
		}
		
		headerCharset = headerCharset.trim();
		
		if (isResponseHTML(msg, source)) { // Check HTML response charset
			// Looking for <META HTTP-EQUIV="Content-Type" CONTENT="...">
			// TODO: could there be more than single "Content-Type" meta per HTML?
			
			List<Element> metaElements = source.getAllElements(HTMLElementName.META);
			if (metaElements != null) {
				for (Element metaElement : metaElements) {
					String httpEquiv = metaElement.getAttributeValue("http-equiv");
					String bodyContentType = metaElement.getAttributeValue("content");
					
					// If META element defines HTTP-EQUIV and CONTENT attributes, 
					// compare charset values 
					if (httpEquiv != null && bodyContentType != null && 
							httpEquiv.equalsIgnoreCase("content-type")) {
						String bodyContentCharset = getBodyContentCharset(bodyContentType);
						if (!headerCharset.equalsIgnoreCase(bodyContentCharset)) {
							raiseAlert(msg, id, getExtraInfoHTMLMessage(bodyContentCharset, 
									headerCharset));
						}
					}
				}
			}				
		} else if (isResponseXML(msg, source)) { // Check XML response charset
			// We're interested in the 'encoding' attribute defined in the XML 
			// declaration tag (<?xml enconding=".."?>
			//
			// TODO: could there be more than one XML declaration tag for a single XML file?
			List<StartTag> xmlDeclarationTags = source.getAllStartTags(
					StartTagType.XML_DECLARATION);
			if (xmlDeclarationTags.size() > 0) {
				StartTag xmlDeclarationTag = xmlDeclarationTags.get(0);
				String encoding = xmlDeclarationTag.getAttributeValue("encoding");
				
				if (!headerCharset.equalsIgnoreCase(encoding)) {
					raiseAlert(msg, id, getExtraInfoXMLMessage(encoding, headerCharset));
				} 
			}
		}
	}
	
	// TODO: Fix up to support other variations of text/html.  
	// FIX: This will match Atom and RSS feeds now, which set text/html but 
	// use &lt;?xml&gt; in content
  	
	private boolean isResponseHTML(HttpMessage message, Source source) {
		String contentType = message.getResponseHeader().getHeader(
				HttpHeader.CONTENT_TYPE);
		if (contentType == null) {
			return false;
		}
		
		return contentType.indexOf("text/html") != -1 || 
				contentType.indexOf("application/xhtml+xml") != -1 ||
				contentType.indexOf("application/xhtml") != -1;
	}
	
	private boolean isResponseXML(HttpMessage message, Source source) {
		return source.isXML();
	}
		
	private String getBodyContentCharset(String bodyContentType) {
		// preconditions
		assert bodyContentType != null;
		
		String charset = null;
		
		bodyContentType = bodyContentType.trim();
		
		int charsetIndex;
		if ((charsetIndex = bodyContentType.indexOf("charset=")) != -1) {
			// 8 is a length of "charset="
			charset = bodyContentType.substring(charsetIndex + 8);	 				
		}
		
		return charset;
	}

	private void raiseAlert(HttpMessage msg, int id, String extraInfo) {
		Alert alert = new Alert(getPluginId(), Alert.RISK_INFO, Alert.CONFIDENCE_LOW,
				getName());
		alert.setDetail(getDescriptionMessage(), msg.getRequestHeader()
				.getURI().toString(), "content-type", getExploitMessage(), extraInfo,
				getSolutionMessage(), getReferenceMessage(), 
				"",	// No Evidence
				0,	// TODO CWE Id
				0,	// TODO WASC Id
				msg);

		parent.raiseAlert(id, alert);
	}

	@Override
	public int getPluginId() {
		return 90011;
	}

	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;
	}

	/*
	 * Rule-associated messages
	 */

	private String getDescriptionMessage() {
		return Constant.messages.getString(MESSAGE_PREFIX + "desc");
	}

	private String getSolutionMessage() {
		return Constant.messages.getString(MESSAGE_PREFIX + "soln");
	}

	private String getReferenceMessage() {
		return Constant.messages.getString(MESSAGE_PREFIX + "refs");
	}

	private String getExploitMessage() {
		return Constant.messages.getString(MESSAGE_PREFIX + "exploit");
	}

	private String getExtraInfoHTMLMessage(String contentCharset,
			String headerCharset) {
		return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo.html", 
				contentCharset, headerCharset);
	}

	private String getExtraInfoXMLMessage(String contentCharset,
			String headerCharset) {
		return Constant.messages.getString(MESSAGE_PREFIX + "extrainfo.xml", 
				contentCharset, headerCharset);
	}
}