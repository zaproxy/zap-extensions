/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Port for the Watcher passive scanner (http://websecuritytool.codeplex.com/) rule {@code
 * CasabaSecurity.Web.Watcher.Checks.CheckPasvSSLInsecureFormPost}
 */
public class InsecureFormPostScanRule extends PluginPassiveScanner {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanbeta.insecureformpost.";

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
        if (!getHelper().isPage200(msg) || !isHttps(msg) || !isResponseHTML(msg, source)) {
            return;
        }

        List<Element> formElements = source.getAllElements(HTMLElementName.FORM);
        for (Element formElement : formElements) {
            String formAction = formElement.getAttributeValue("action");
            if (formAction != null && formAction.trim().toLowerCase().startsWith("http://")) {
                raiseAlert(msg, id, formElement);
            }
        }
    }

    private boolean isHttps(HttpMessage msg) {
        String scheme = msg.getRequestHeader().getURI().getScheme();
        if ("https".equals(scheme)) {
            return true;
        }

        return false;
    }

    // TODO: Fix up to support other variations of text/html.
    // FIX: This will match Atom and RSS feeds now, which set text/html but
    // use &lt;?xml&gt; in content

    // TODO: these methods have been extracted from CharsetMismatchScanner
    // I think we should create helper methods for them
    private boolean isResponseHTML(HttpMessage message, Source source) {
        String contentType = message.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE);
        if (contentType == null) {
            return false;
        }

        return contentType.indexOf("text/html") != -1
                || contentType.indexOf("application/xhtml+xml") != -1
                || contentType.indexOf("application/xhtml") != -1;
    }

    private void raiseAlert(HttpMessage msg, int id, Element formElement) {
        newAlert()
                .setRisk(Alert.RISK_MEDIUM)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(getDescriptionMessage())
                .setOtherInfo(getExtraInfoMessage(msg, formElement))
                .setSolution(getSolutionMessage())
                .setReference(getReferenceMessage())
                .setCweId(16) // CWE-16: Configuration
                .setWascId(15) // WASC-15: Application Misconfiguration
                .raise();
    }

    @Override
    public int getPluginId() {
        return 10042;
    }

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
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

    private String getExtraInfoMessage(HttpMessage msg, Element formElement) {
        return Constant.messages.getString(
                MESSAGE_PREFIX + "extrainfo",
                msg.getRequestHeader().getURI().toString(),
                formElement.toString());
    }
}
