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
package org.zaproxy.zap.extension.jsfviewstatepscan;

import java.io.IOException;
import java.text.MessageFormat;
import java.util.List;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.extension.encoder.Base64;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * A port from a Watcher passive scanner (http://websecuritytool.codeplex.com/)
 * rule {@code CasabaSecurity.Web.Watcher.Checks.CheckPasvJavaServerFacesViewState}
 * <p>
 * The following class description has been taken from the corresponding Watcher rule:
 * <p>
 * 
 * <pre>
 * Look for insecure ViewState used by Sun Java Mojarra (http://java.sun.com/javaee/javaserverfaces/) and
 * Apache MyFaces (http://myfaces.apache.org/).  Both are implementations of the JavaServer Faces standard 
 * and both handle and reference ViewState the same way.  
 * By default the ViewState data they pass between client and server is insecure and subject to tampering
 * and XSS attacks - see the advisory https://www.trustwave.com/spiderlabs/advisories/TWSL2010-001.txt.
 * </pre>
 * <p>
 * 
 * <pre>
 * David Byrne described it as this:
 * Regarding detection on JSF (Apache MyFaces & Sun Mojarra), they are Java object streams, so the format 
 * is fairly predictable. The simplest way is probably to just check the value for plain text strings. 
 * If it's unencrypted, there should be some Java class names, etc in there. There are a few different 
 * encodings that can be used though. All of the JSF view state's I've seen are base64 encoded, 
 * although I don't think they have to be. After decoding the base64, some may be compressed 
 * with the gzip algorithm (which is the default).
 * </pre>
 */
public class InsecureJSFViewStatePassiveScanner extends PluginPassiveScanner {

	private PassiveScanThread parent = null;

	/**
	 * contains the internationalisation (i18n) messages. Must be statically
	 * initialised, since messages is accessed before the plugin is initialised
	 * (using init)
	 */
	private final ResourceBundle messages = ResourceBundle.getBundle(this.getClass()
			.getPackage().getName()
			+ ".Messages", Constant.getLocale());
	
	private static final String MESSAGE_PREFIX = "insecurejsfviewstate.";

	@Override
	public void setParent(PassiveScanThread parent) {
		this.parent = parent;
	}

	@Override
	public void scanHttpRequestSend(HttpMessage msg, int id) {
	}

	private int getId() {
		return 90001; // This is be changed if included in the ZAP code base
	}

	@Override
	public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
		if (msg.getResponseBody().length() > 0
				&& msg.getResponseHeader().isText()) {
			List<Element> inputElements = source
					.getAllElements(HTMLElementName.INPUT);
			if (inputElements != null) {
				for (Element inputElement : inputElements) {

					// Find ones where id="javax.faces.ViewState"
					//
					// TODO: Other possible field names include:
					// jsf_state_64
					// jsf_sequence
					// jsf_tree
					// jsf_tree_64
					// jsf_viewid
					// jsf_state
					String inputElementId = inputElement.getAttributeValue("id");
					if ("javax.faces.viewstate".equalsIgnoreCase(inputElementId)) {
						// Get the ViewState value
						String inputElementValue = inputElement.getAttributeValue("value");
						// Server-side ViewState usually comes down as an ID
						// value like
						// _id16683
						// Ignoring these for now. Underscore is not a valid
						// Base64 character
						// so it's safe to ignore this.
						if (inputElementValue == null || inputElementValue.startsWith("_")) {
							return;
						}

						// If the ViewState is not secured cryptographic
						// protections then raise an alert.
						if (!isViewStateSecure(inputElementValue, msg.getRequestBody().getCharset())) {
							raiseAlert(msg, id, inputElementValue);
							// -The scanner may stop now as an issue was already found.
							return;
						}
					}
				}
			}
		}
	}

	/**
	 * Checks whether the specified viewState is secure or possibly not
	 * 
	 * @param viewState view state string
	 * @param charset viewState string encoding
	 * @return {@code true} if {@code viewState} is cryptographically secure, 
	 * {@code false} otherwise (there might be false positives and false
	 * negatives)
	 */
	private boolean isViewStateSecure(String viewState, String charset) {
		if (viewState == null || viewState.equals("")) {
			return true;
		}

		// /////////////////////////////
		// Base64 decode the ViewState and decompress ViewState from gzip format (the default), 
		// or handle it as uncompressed (which is possible).
		//
		// There's two possibilities at this point, either the decoded ViewState
		// is uncompressed or it's compressed.
		// If it's uncompressed then we can treat it as a string right away.
		///
		// TODO: Some ViewState can use other encoding forms, research and add
		// support for these.
		//
		// TODO: Could other compression forms be used?		

		byte[] viewStateDecodeBytes;
		try {
			// The content is automatically uncompressed if it was compressed (with GZIP).
			viewStateDecodeBytes = Base64.decode(viewState, Base64.NO_OPTIONS);
		} catch (IOException e) {
			// ViewState might be unencoded which is theoretically possible.
			return isRawViewStateSecure(viewState);
		}
		
		String viewStateDecoded = new String(viewStateDecodeBytes);

		return isRawViewStateSecure(viewStateDecoded);
	}

	private boolean isRawViewStateSecure(String viewState) {
		if (viewState == null || viewState.equals("")) {
			return true;
		}

		// Look for string values like 'java' to determine that it's insecure.
		// TODO: Improve this to look for more than just 'java'. It's possible
		// we could even have a false positive here.
		// Usually there will be Java class names in there as well as other
		// stuff.
		if (viewState.contains("java")) {
			return false;
		}

		return true;
	}

	private void raiseAlert(HttpMessage msg, int id, String viewState) {
		Alert alert = new Alert(getId(), Alert.RISK_MEDIUM, Alert.SUSPICIOUS,
				getName());
		alert.setDetail(
				getDescription(),
				msg.getRequestHeader().getURI().toString(),
				"",
				"",
				getString(MESSAGE_PREFIX + "extrainfo", viewState),
				getSolution(),
				getReference(),
				msg);

		parent.raiseAlert(id, alert);
	}

	@Override
	public String getName() {
		return getString(MESSAGE_PREFIX + "name");
	}

	private String getDescription() {
		return getString(MESSAGE_PREFIX + "desc");
	}

	private String getSolution() {
		return getString(MESSAGE_PREFIX + "soln");
	}

	private String getReference() {
		return getString(MESSAGE_PREFIX + "refs");
	}

	/**
	 * Returns an internationalized message for the specified key
	 * 
	 * @param key the key to look up the internationalized message
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
	 * gets the internationalised message corresponding to the key, using the parameters supplied
	 * @param key the key to look up the internationalised message
	 * @param params the parameters used to internationalise the message
	 * @return the internationalised message corresponding to the key, using the parameters supplied
	 */
	public String getString(String key, Object... params  ) {
		try {
			return MessageFormat.format(messages.getString(key), params);
		} catch (MissingResourceException e) {
			return '!' + key + '!';
		}
	}	
}
