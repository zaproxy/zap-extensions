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
package org.zaproxy.zap.extension.charsetmismatchpscan;

import java.text.MessageFormat;
import java.util.List;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import net.htmlparser.jericho.StartTag;
import net.htmlparser.jericho.StartTagType;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * A port from a Watcher passive scanner (http://websecuritytool.codeplex.com/)
 * rule {@code CasabaSecurity.Web.Watcher.Checks.CheckPasvCharsetMismatch}
 * 
 * http://websecuritytool.codeplex.com/SourceControl/changeset/view/17f2e3ded58f
 * #Watcher%20Check%20Library%2fCheck.Pasv.Charset.Mismatch.cs
 */
public class CharsetMismatchPassiveScanner extends PluginPassiveScanner {

	private PassiveScanThread parent = null;

	/**
	 * contains the internationalisation (i18n) messages. Must be statically
	 * initialised, since messages is accessed before the plugin is initialised
	 * (using init)
	 */
	private final ResourceBundle messages = ResourceBundle.getBundle(this
			.getClass().getPackage().getName()
			+ ".Messages", Constant.getLocale());

	/**
	 * Prefix for internationalized messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "charsetmismatch.";

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.zaproxy.zap.extension.pscan.PassiveScanner#getName()
	 */
	@Override
	public String getName() {
		return getString(MESSAGE_PREFIX + "name");
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// do nothing
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.zaproxy.zap.extension.pscan.PassiveScanner#scanHttpResponseReceive
	 * (org.parosproxy.paros.network.HttpMessage, int,
	 * net.htmlparser.jericho.Source)
	 */
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
					if (httpEquiv != null && bodyContentType != null && httpEquiv.equalsIgnoreCase("content-type")) {
						String bodyContentCharset = getBodyContentCharset(bodyContentType);
						if (!headerCharset.equalsIgnoreCase(bodyContentCharset)) {
							raiseAlert(msg, id, getExtraInfoHTMLMessage(bodyContentCharset, headerCharset));
						}
					}
				}
			}				
		} else if (isResponseXML(msg, source)) { // Check XML response charset
			// We're interested in the 'encoding' attribute defined in the XML 
			// declaration tag (<?xml enconding=".."?>
			//
			// TODO: could there be more than one XML declaration tag for a single XML file?
			List<StartTag> xmlDeclarationTags = source.getAllStartTags(StartTagType.XML_DECLARATION);
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
	// FIX: This will match Atom and RSS feeds now, which set text/html but use &lt;?xml&gt; in content
  	
	private boolean isResponseHTML(HttpMessage message, Source source) {
		String contentType = message.getResponseHeader().getHeader("content-type");
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
			charset = bodyContentType.substring(charsetIndex + 8);	 // 8 is a length of "charset="		
		}
		
		return charset;
	}

	private void raiseAlert(HttpMessage msg, int id, String extraInfo) {
		Alert alert = new Alert(getId(), Alert.RISK_INFO, Alert.SUSPICIOUS,
				getName());
		alert.setDetail(getDescriptionMessage(), msg.getRequestHeader()
				.getURI().toString(), extraInfo, getExploitMessage(), "",
				getSolutionMessage(), getReferenceMessage(), msg);

		parent.raiseAlert(id, alert);
	}

	private int getId() {
		return 90011;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.zaproxy.zap.extension.pscan.PassiveScanner#setParent(org.zaproxy.
	 * zap.extension.pscan.PassiveScanThread)
	 */
	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;
	}

	/**
	 * Returns an internationalized message for the specified key
	 * 
	 * @param key
	 *            the key to look up the internationalized message
	 * @return the internationalized message corresponding to the key
	 */
	private String getString(String key) {
		try {
			return messages.getString(key);
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		}
	}

	/**
	 * Returns an internationalized message for the specified key, using the
	 * parameters supplied
	 * 
	 * @param key
	 *            the key to look up the internationalized message
	 * @param params
	 *            the parameters to use for the internationalized message
	 * @return the internationalized message corresponding to the key, using the
	 *         parameters supplied
	 */
	public String getString(String key, Object... params) {
		try {
			return MessageFormat.format(messages.getString(key), params);
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		}
	}

	/*
	 * Rule-associated messages
	 */

	private String getDescriptionMessage() {
		return getString(MESSAGE_PREFIX + "desc");
	}

	private String getSolutionMessage() {
		return getString(MESSAGE_PREFIX + "soln");
	}

	private String getReferenceMessage() {
		return getString(MESSAGE_PREFIX + "refs");
	}

	private String getExploitMessage() {
		return getString(MESSAGE_PREFIX + "exploit");
	}

	private String getExtraInfoHTMLMessage(String contentCharset,
			String headerCharset) {
		return getString(MESSAGE_PREFIX + "extrainfo.html", contentCharset,
				headerCharset);
	}

	private String getExtraInfoXMLMessage(String contentCharset,
			String headerCharset) {
		return getString(MESSAGE_PREFIX + "extrainfo.xml", contentCharset,
				headerCharset);
	}
}
