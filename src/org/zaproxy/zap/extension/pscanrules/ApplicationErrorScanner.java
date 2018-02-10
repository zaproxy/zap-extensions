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

import net.htmlparser.jericho.Source;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.utils.ContentMatcher;

/**
 * Plugin able to analyze the content for Application Error messages. The plugin
 * find the first occurrence of an exact match or a regex pattern matching
 * according to an external file definition. The vulnerability can be included
 * inside the Information Leakage family (WASC-13)
 *
 * @author yhawke 2013
 */
public class ApplicationErrorScanner extends PluginPassiveScanner {

	/**
	 * Prefix for internationalised messages used by this rule
	 */
	private static final String MESSAGE_PREFIX = "pscanrules.applicationerrorscanner.";
	
    // Name of the file related to pattern's definition list
    private static final String APP_ERRORS_FILE = "/org/zaproxy/zap/extension/pscanrules/resources/application_errors.xml";

    // Inner Content Matcher component with pattern definitions
    private static final ContentMatcher matcher = 
    		ContentMatcher.getInstance(ApplicationErrorScanner.class.getResourceAsStream(APP_ERRORS_FILE));
    // Inner Thread Parent variable
    private PassiveScanThread parent = null;

    /**
     * Get this plugin id
     *
     * @return the ZAP id
     */
    @Override
    public int getPluginId() {
        return 90022;
    }

    /**
     * Get the plugin name
     *
     * @return the plugin name
     */
    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    private String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    private String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    private String getReference() {
        return null;
    }

    private int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    private int getCweId() {
        return 200;
    }

    private int getWascId() {
        return 13;
    }

    /**
     * Set the Scanner thread parent object
     *
     * @param parent the PassiveScanThread parent object
     */
    @Override
    public void setParent(PassiveScanThread parent) {
        this.parent = parent;
    }

    /**
     * Scan the request. Currently it does nothing.
     *
     * @param msg the HTTP message
     * @param id the id of the request
     */
    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // Do Nothing it's related to response managed
    }

    /**
     * Perform the passive scanning of application errors inside the response
     * content
     *
     * @param msg the message that need to be checked
     * @param id the id of the session
     * @param source the source code of the response
     */
    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {

        // First check if it's an INTERNAL SERVER ERROR
        int status = msg.getResponseHeader().getStatusCode();
        if (status == HttpStatusCode.INTERNAL_SERVER_ERROR) {
            // We found it!
            // The AS raise an Internal Error
            // so a possible disclosure can be found
            raiseAlert(msg, id, msg.getResponseHeader().getPrimeHeader());

        } else if (status != HttpStatusCode.NOT_FOUND) {
            String evidence = matcher.findInContent(msg.getResponseBody().toString());
            if (evidence != null) {
                // We found it!
                // There exists a positive match of an
                // application error occurrence
                raiseAlert(msg, id, evidence);
            }
        }
    }
        
    // Internal service method for alert management
    private void raiseAlert(HttpMessage msg, int id, String evidence) {
        // Raise an alert according to Passive Scan Rule model
        // description, uri, param, attack, otherInfo, 
        // solution, reference, evidence, cweId, wascId, msg
        Alert alert = new Alert(getPluginId(), getRisk(), Alert.CONFIDENCE_MEDIUM, getName());
        alert.setDetail(
                getDescription(),
                msg.getRequestHeader().getURI().toString(),
                "",
                "",
                "",
                getSolution(),
                getReference(),
                evidence, // evidence
                getCweId(), // CWE Id
                getWascId(), // WASC Id - Info leakage
                msg);

        parent.raiseAlert(id, alert);
    }
}
