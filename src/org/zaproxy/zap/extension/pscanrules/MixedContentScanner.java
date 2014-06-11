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
package org.zaproxy.zap.extension.pscanrules;

import java.util.ArrayList;
import java.util.List;

import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;

import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;


public class MixedContentScanner extends PluginPassiveScanner {

	private PassiveScanThread parent = null;

	@Override
	public void setParent (PassiveScanThread parent) {
		this.parent = parent;
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
		// Ignore
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		if (!msg.getRequestHeader().isSecure()) {
			// If SSL isn't used then this check isnt relevant
			return;
		}
		List<MixedContent> list = new ArrayList<MixedContent>();
		boolean incScript = false;
		
		if (msg.getResponseBody().length() > 0 && msg.getResponseHeader().isText()){
			List<Element> sourceElements = source.getAllElements();
			if (sourceElements != null) {
				for (Element sourceElement : sourceElements) {
					if (addAttsContainingHttpContent(sourceElement, "src", list)) {
						if (HTMLElementName.SCRIPT.equals(sourceElement.getName())) {
							// Considered to be more serious
							incScript = true;
						}
					}	
					addAttsContainingHttpContent(sourceElement, "background", list);
					addAttsContainingHttpContent(sourceElement, "classid", list);
					addAttsContainingHttpContent(sourceElement, "codebase", list);
					addAttsContainingHttpContent(sourceElement, "data", list);
					addAttsContainingHttpContent(sourceElement, "icon", list);
					addAttsContainingHttpContent(sourceElement, "usemap", list);
					
					switch (this.getLevel()) {
					case LOW:
					case MEDIUM:
						// These are a bit more debatable, so dont do them on the HIGH setting
						addAttsContainingHttpContent(sourceElement, "action", list);
						addAttsContainingHttpContent(sourceElement, "formaction", list);
						break;
					default:
						// No other checks
					}
				}	
			}
			final int numberOfMixedElements = list.size();
			if (numberOfMixedElements > 0) {
				StringBuilder sb = new StringBuilder(numberOfMixedElements * 40);
				for (MixedContent mc : list) {
					sb.append("tag=");
					sb.append(mc.getTag());
					sb.append(' ');
					sb.append(mc.getAtt());
					sb.append('=');
					sb.append(mc.getValue());
					sb.append('\n');
				}

				this.raiseAlert(msg, id, list.get(0).getValue(), sb.toString(), incScript);
			}
		}
	}
	
	private boolean addAttsContainingHttpContent(Element sourceElement, String attribute, List<MixedContent> list) {
		String val = sourceElement.getAttributeValue(attribute);
		if (val != null && val.toLowerCase().startsWith("http:")) {
			list.add(new MixedContent(sourceElement.getName(), attribute, val));
			return true;
		}
		return false;
	}
	
	private void raiseAlert(HttpMessage msg, int id, String first, String all, boolean incScript) {
		String name = "Secure page includes mixed content";
		int risk = Alert.RISK_LOW;
		if (incScript) {
			name = "Secure page includes mixed content, including scripts";
			risk = Alert.RISK_MEDIUM;
		}
	    Alert alert = new Alert(getPluginId(), risk, Alert.WARNING, name);
    	alert.setDetail(
    	    "The page includes mixed content, ie content accessed via http instead of https.", 
    	    msg.getRequestHeader().getURI().toString(),
    	    "", first, all,
    	    "A page that is available over TLS must be comprised completely of content which is transmitted over TLS. \n" +
    	    "The page must not contain any content that is transmitted over unencrypted HTTP.\n" +
    	    "This includes content from unrelated third party sites.",
            "https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet", 
            first, // evidence
            0,	// TODO CWE Id
            0,	// TODO WASC Id
            msg);
	
    	parent.raiseAlert(id, alert);

	}

	@Override
	public int getPluginId() {
		return 10040;
	}

	@Override
	public String getName() {
		return "Secure pages including mixed content";
	}
	
	private class MixedContent {
		private String tag;
		private String att;
		private String value;
		
		public MixedContent(String tag, String att, String value) {
			super();
			this.tag = tag;
			this.att = att;
			this.value = value;
		}

		public String getTag() {
			return tag;
		}

		public String getAtt() {
			return att;
		}

		public String getValue() {
			return value;
		}
		
	}
}
