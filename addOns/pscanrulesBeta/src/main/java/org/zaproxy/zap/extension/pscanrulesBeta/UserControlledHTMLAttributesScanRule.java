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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import net.htmlparser.jericho.Attribute;
import net.htmlparser.jericho.Attributes;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Port for the Watcher passive scanner (http://websecuritytool.codeplex.com/) rule {@code
 * CasabaSecurity.Web.Watcher.Checks.CheckPasvUserControlledHTMLAttributes}
 */
public class UserControlledHTMLAttributesScanRule extends PluginPassiveScanner {

    /** Prefix for internationalized messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanbeta.usercontrolledhtmlattributes.";

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
        if (msg.getResponseHeader().getStatusCode() != 200 || !isResponseHTML(msg, source)) {
            return;
        }

        List<Element> htmlElements = source.getAllElements();
        if (htmlElements.size() == 0) {
            return;
        }

        Set<HtmlParameter> params = new TreeSet<HtmlParameter>(msg.getFormParams());
        params.addAll(msg.getUrlParams());
        if (params.size() == 0) {
            return;
        }

        checkHtmlElements(msg, id, params, htmlElements);
    }

    /*
     Mainly looks to see if user-input controls certain attributes.  If the input is a URL, this attempts
     to see if the scheme or domain can be controlled.  If it's not, it attempts to see if the attribute
     data starts with the user-data.
    */
    private void checkHtmlElements(
            HttpMessage msg, int id, Set<HtmlParameter> params, List<Element> listOfHtmlElements) {
        for (Element element : listOfHtmlElements) {
            checkHtmlElement(msg, id, params, element);
        }
    }

    private void checkHtmlElement(
            HttpMessage msg, int id, Set<HtmlParameter> params, Element htmlElement) {
        Attributes attributes = htmlElement.getAttributes();
        if (attributes == null) {
            return;
        }

        for (Attribute attribute : attributes) {
            checkHtmlAttribute(msg, id, params, htmlElement, attribute);
        }
    }

    private void checkHtmlAttribute(
            HttpMessage msg,
            int id,
            Set<HtmlParameter> params,
            Element htmlElement,
            Attribute attribute) {
        String attrValue = attribute.getValue();
        if (attrValue == null) {
            return;
        }

        attrValue = attrValue.toLowerCase();

        // special handling of meta tag
        if (htmlElement.getName().equalsIgnoreCase(HTMLElementName.META)
                && attribute.getName().equalsIgnoreCase("content")) {
            if (attrValue.matches("^\\s*?[0-9]+?\\s*?;\\s*?url\\s*?=.*")) {
                attrValue = attrValue.substring(attrValue.indexOf("url=") + 4).trim();
            }
        }

        if (attrValue.length() == 0) {
            return;
        }

        String protocol = null;
        String domain = null;
        String token = null;

        // if contains protocol/domain name separator
        if (attrValue.indexOf("://") > 0) {
            URL url;
            try {
                url = new URL(attrValue);
            } catch (MalformedURLException e) {
                return;
            }
            // get protocol
            protocol = url.getProtocol();

            // get domain name
            domain = url.getAuthority();

            // token
            token = url.getQuery();
            // get up to first slash
            if (token != null && token.indexOf("/") > 0) {
                token = token.substring(0, token.indexOf("/"));
            }
        }

        // It's a local path, or it's not a resource.
        // Proceed later expecting the attribute value
        // might start with the user-input.

        for (HtmlParameter param : params) {
            String paramValue = param.getValue();
            if (paramValue == null) {
                return;
            }

            paramValue = paramValue.toLowerCase();

            // Special handling of meta tag.
            // If I were just looking to see if the meta tag 'contains' the user input,
            // we'd wind up with lots of false positives.
            // To avoid this, I  parse the meta tag values based on a set of delimeters,
            // such as ; =  and ,.  This is similar to what the Cookie poisoning
            // check does.
            if (htmlElement.getName().equalsIgnoreCase(HTMLElementName.META)
                    && attribute.getName().equalsIgnoreCase("content")) {
                // False Positive Reduction
                // We have a check for meta tag charset already, so get out of here.
                if (attrValue.contains("charset")) {
                    continue;
                }

                for (String s : attrValue.split("[;=,]")) {
                    if (s.equals(paramValue)) {
                        raiseAlert(msg, id, htmlElement, attribute, param, attrValue);
                        return; // Only need one alert
                    }
                }
            }

            // False Positive Reduction
            // I want the value length to be greater than 1 to avoid all the false positives
            // we're seeing when the input is limited to a single character.
            if (paramValue.length() > 1) {
                // See if the user-input can control the start of the attribute data.
                if (attrValue.startsWith(paramValue)
                        || paramValue.equalsIgnoreCase(protocol)
                        || paramValue.equalsIgnoreCase(domain)
                        || paramValue.equalsIgnoreCase(token)
                        || (attrValue.indexOf("://") > 0 && paramValue.indexOf(attrValue) == 0)) {
                    raiseAlert(msg, id, htmlElement, attribute, param, attrValue);
                }
            }

            // Make up for the false positive reduction by by being
            // sure to catch cases where a single character may control the attribute.
            // UPDATE: This case is too common and annoyingly rife with false positives.

            // if (val.Length == 1 && att.Equals(val) )
            // {
            //    AssembleAlert(element.tag, attribute, parm, val, value);
            // }

        }
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

    private void raiseAlert(
            HttpMessage msg,
            int id,
            Element htmlElement,
            Attribute htmlAttribute,
            HtmlParameter param,
            String userControlledValue) {
        newAlert()
                .setRisk(Alert.RISK_INFO)
                .setConfidence(Alert.CONFIDENCE_LOW)
                .setDescription(getDescriptionMessage())
                .setParam(param.getName())
                .setOtherInfo(
                        getExtraInfoMessage(
                                msg,
                                htmlElement.getName(),
                                htmlAttribute.getName(),
                                param,
                                userControlledValue))
                .setSolution(getSolutionMessage())
                .setReference(getReferenceMessage())
                .setCweId(20) // CWE-20: Improper Input Validation
                .setWascId(20) // WASC-20: Improper Input Handling
                .raise();
    }

    @Override
    public int getPluginId() {
        return 10031;
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

    private String getExtraInfoMessage(
            HttpMessage msg,
            String tag,
            String attr,
            HtmlParameter param,
            String userControlledValue) {
        return Constant.messages.getString(
                MESSAGE_PREFIX + "extrainfo",
                msg.getRequestHeader().getURI().toString(),
                tag,
                attr,
                param.getName(),
                param.getValue(),
                userControlledValue);
    }
}
