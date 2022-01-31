/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Enumeration;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;
import org.zaproxy.addon.network.server.Server;

public class HttPoxyScanRule extends AbstractAppPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanbeta.httpoxy.";

    private static final int PLUGIN_ID = 10107;
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A06_VULN_COMP,
                    CommonAlertTag.OWASP_2017_A09_VULN_COMP);

    private static final Logger log = LogManager.getLogger(HttPoxyScanRule.class);

    @Override
    public int getCategory() {
        return Category.SERVER;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 20; // WASC-20 Improper Input Handling
    }

    @Override
    public int getWascId() {
        return 20; // Improper Input Validation
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "soln");
    }

    @Override
    public void init() {
        ExtensionNetwork ext =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionNetwork.class);
        if (ext == null) {
            getParent()
                    .pluginSkipped(this, Constant.messages.getString(MESSAGE_PREFIX + "skipped"));
        }
    }

    @Override
    public void scan() {
        // Set up a listener using all interfaces on another port
        HttpoxyListener listener = new HttpoxyListener();
        try (Server server =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionNetwork.class)
                        .createHttpServer(listener)) {
            int proxyPort = server.start("0.0.0.0");
            Enumeration<NetworkInterface> allInterfaces = NetworkInterface.getNetworkInterfaces();

            // Try all of the available interfaces as we dont know which one(s)
            // will be available to the target server
            while (allInterfaces.hasMoreElements()) {
                NetworkInterface ni = allInterfaces.nextElement();
                Enumeration<InetAddress> inetAddrs = ni.getInetAddresses();
                while (inetAddrs.hasMoreElements()) {
                    InetAddress inetAddr = inetAddrs.nextElement();
                    String hostPort = inetAddr.getHostAddress() + ":" + proxyPort;

                    HttpMessage newRequest = getNewMsg();
                    newRequest.getRequestHeader().setHeader("Proxy", hostPort);
                    try {
                        sendAndReceive(newRequest, false);
                    } catch (Exception e) {
                        // Ignore
                    }

                    if (listener.isMsgReceived()) {
                        // the server is vulnerable
                        newAlert()
                                .setConfidence(Alert.CONFIDENCE_HIGH)
                                .setUri(getBaseMsg().getRequestHeader().getURI().toString())
                                .setAttack("Proxy: " + hostPort)
                                .setOtherInfo(
                                        Constant.messages.getString(
                                                MESSAGE_PREFIX + "otherinfo", listener.getMsgUrl()))
                                .setMessage(newRequest)
                                .raise();

                        // no point in continuing
                        return;
                    }
                }
            }
        } catch (Exception e) {
            log.debug(e.getMessage(), e);
        }
    }

    private class HttpoxyListener implements HttpMessageHandler {

        private boolean msgReceived;
        private String msgUrl;

        @Override
        public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
            ctx.close();

            this.msgReceived = true;
            this.msgUrl = msg.getRequestHeader().getURI().toString();
            log.debug("Received request {}", msgUrl);
        }

        public boolean isMsgReceived() {
            return msgReceived;
        }

        public String getMsgUrl() {
            return msgUrl;
        }
    }
}
