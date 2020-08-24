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
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PassiveScanThread;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

/**
 * Server Header Version Information Leak passive scan rule
 * https://github.com/zaproxy/zaproxy/issues/1169
 *
 * @author kingthorin+owaspzap@gmail.com
 */
public class ServerHeaderInfoLeakScanRule extends PluginPassiveScanner {

    private static final int PLUGIN_ID = 10036;

    private static final Logger logger = Logger.getLogger(ServerHeaderInfoLeakScanRule.class);

    private static final Pattern VERSION_PATTERN = Pattern.compile(".*\\d.*");

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

        List<String> serverOption = msg.getResponseHeader().getHeaderValues("Server");
        if (!serverOption.isEmpty()) { // Header Found
            // It is set so lets check it. Should only be one but it's a vector so iterate to be
            // sure.
            for (String serverDirective : serverOption) {
                boolean matched = VERSION_PATTERN.matcher(serverDirective).matches();
                if (matched) { // See if there's any version info.
                    // While an alpha string might be the server type (Apache, Netscape, IIS, etc.)
                    // that's much less of a head-start than actual version details.
                    raiseAlert(
                            Alert.RISK_LOW,
                            Alert.CONFIDENCE_HIGH,
                            Constant.messages.getString(
                                    "pscanbeta.serverheaderversioninfoleak.name"),
                            Constant.messages.getString(
                                    "pscanbeta.serverheaderversioninfoleak.desc"),
                            Constant.messages.getString(
                                    "pscanbeta.serverheaderinfoleak.general.soln"),
                            Constant.messages.getString(
                                    "pscanbeta.serverheaderinfoleak.general.refs"),
                            serverDirective);
                } else if (Plugin.AlertThreshold.LOW.equals(this.getAlertThreshold())) {
                    raiseAlert(
                            Alert.RISK_INFO,
                            Alert.CONFIDENCE_HIGH,
                            Constant.messages.getString("pscanbeta.serverheaderinfoleak.name"),
                            Constant.messages.getString("pscanbeta.serverheaderinfoleak.desc"),
                            Constant.messages.getString(
                                    "pscanbeta.serverheaderinfoleak.general.soln"),
                            Constant.messages.getString(
                                    "pscanbeta.serverheaderinfoleak.general.refs"),
                            serverDirective);
                }
            }
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
        return Constant.messages.getString("pscanbeta.serverheader.rule.name");
    }

    private void raiseAlert(
            int risk,
            int confidence,
            String name,
            String desc,
            String soln,
            String refs,
            String evidence) {
        newAlert()
                .setName(name)
                .setRisk(risk)
                .setConfidence(confidence)
                .setDescription(desc)
                .setSolution(soln)
                .setReference(refs)
                .setEvidence(evidence)
                .setCweId(200)
                .setWascId(13)
                .raise();
    }
}
