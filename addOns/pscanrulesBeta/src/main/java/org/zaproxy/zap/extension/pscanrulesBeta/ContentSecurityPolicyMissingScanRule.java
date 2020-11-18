/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Content Security Policy Header Missing passive scan rule
 * https://github.com/zaproxy/zaproxy/issues/1169
 *
 * @author kingthorin+owaspzap@gmail.com
 */
public class ContentSecurityPolicyMissingScanRule extends PluginPassiveScanner {

    private static final String MESSAGE_PREFIX = "pscanbeta.contentsecuritypolicymissing.";
    private static final int PLUGIN_ID = 10038;

    private static final Logger logger =
            Logger.getLogger(ContentSecurityPolicyMissingScanRule.class);

    @Override
    public void setParent(PassiveScanThread parent) {
        // Nothing to do.
    }

    @Override
    public void scanHttpRequestSend(HttpMessage msg, int id) {
        // Only checking the response for this plugin
    }

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        long start = System.currentTimeMillis();

        if ((!msg.getResponseHeader().isHtml()
                        || HttpStatusCode.isRedirection(msg.getResponseHeader().getStatusCode()))
                && !AlertThreshold.LOW.equals(this.getAlertThreshold())) {
            // Only really applies to HTML responses, but also check on Low threshold
            return;
        }

        // Get the various CSP headers
        boolean cspHeaderFound = false,
                cspROHeaderFound = false,
                xCspHeaderFound = false,
                xWebKitHeaderFound = false;

        // Content-Security-Policy is supported by Chrome 25+, Firefox 23+, Safari 7+, but not but
        // Internet Exploder
        List<String> cspOptions =
                msg.getResponseHeader().getHeaderValues("Content-Security-Policy");
        if (!cspOptions.isEmpty()) {
            cspHeaderFound = true;
        }

        List<String> cspROOptions =
                msg.getResponseHeader().getHeaderValues("Content-Security-Policy-Report-Only");
        if (!cspROOptions.isEmpty()) {
            cspROHeaderFound = true;
        }

        // X-Content-Security-Policy is an older header, supported by Firefox 4.0+, and IE 10+ (in a
        // limited fashion)
        List<String> xcspOptions =
                msg.getResponseHeader().getHeaderValues("X-Content-Security-Policy");
        if (!xcspOptions.isEmpty()) {
            xCspHeaderFound = true;
        }

        // X-WebKit-CSP is supported by Chrome 14+, and Safari 6+
        List<String> xwkcspOptions = msg.getResponseHeader().getHeaderValues("X-WebKit-CSP");
        if (!xwkcspOptions.isEmpty()) {
            xWebKitHeaderFound = true;
        }

        // TODO: parse the CSP values out, and look at them in more detail.  In particular, look for
        // things like...
        // script-src *
        // style-src *
        // img-src *
        // connect-src *
        // font-src *
        // object-src *
        // media-src *
        // frame-src *
        // script-src 'unsafe-inline'
        // script-src 'unsafe-eval'

        if (!cspHeaderFound
                || (AlertThreshold.LOW.equals(this.getAlertThreshold())
                        && (!xCspHeaderFound || !xWebKitHeaderFound))) {
            // Always report if the latest header isnt found,
            // but only report if the older ones arent present at Low threshold
            newAlert()
                    .setRisk(Alert.RISK_MEDIUM)
                    .setConfidence(Alert.CONFIDENCE_HIGH)
                    .setDescription(getAlertAttribute("desc"))
                    .setSolution(getAlertAttribute("soln"))
                    .setReference(getAlertAttribute("refs"))
                    .setCweId(16) // CWE-16: Configuration
                    .setWascId(15) // WASC-15: Application Misconfiguration
                    .raise();
        }

        if (cspROHeaderFound) {
            newAlert()
                    .setName(getAlertAttribute("ro.name"))
                    .setRisk(Alert.RISK_INFO)
                    .setConfidence(Alert.CONFIDENCE_HIGH)
                    .setDescription(getAlertAttribute("ro.desc"))
                    .setSolution(getAlertAttribute("soln"))
                    .setReference(getAlertAttribute("ro.refs"))
                    .setCweId(16) // CWE-16: Configuration
                    .setWascId(15) // WASC-15: Application Misconfiguration
                    .raise();
        }

        if (logger.isDebugEnabled()) {
            logger.debug(
                    "\tScan of record "
                            + id
                            + " took "
                            + (System.currentTimeMillis() - start)
                            + " ms");
        }
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return getAlertAttribute("name");
    }

    private String getAlertAttribute(String key) {
        return Constant.messages.getString(MESSAGE_PREFIX + key);
    }
}
