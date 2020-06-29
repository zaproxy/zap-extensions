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
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.proxy.OverrideMessageProxyListener;
import org.parosproxy.paros.core.proxy.ProxyServer;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

public class HttPoxyScanRule extends AbstractAppPlugin {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanbeta.httpoxy.";

    private static final int PLUGIN_ID = 10107;

    private static final Logger log = Logger.getLogger(HttPoxyScanRule.class);

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
    public void scan() {
        // Set up a listener using all interfaces on another port
        ProxyServer proxy;
        proxy = new ProxyServer();
        HttpoxyListener listener = new HttpoxyListener();
        proxy.addOverrideMessageProxyListener(listener);
        int proxyPort = proxy.startServer(null, 0, true);

        try {
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
        } finally {
            proxy.stopServer();
        }
    }

    private class HttpoxyListener implements OverrideMessageProxyListener {

        private boolean msgReceived;
        private String msgUrl;

        @Override
        public int getArrangeableListenerOrder() {
            return 0;
        }

        @Override
        public boolean onHttpRequestSend(HttpMessage msg) {
            this.msgReceived = true;
            this.msgUrl = msg.getRequestHeader().getURI().toString();
            log.debug("Received request " + msgUrl);
            return true;
        }

        @Override
        public boolean onHttpResponseReceived(HttpMessage msg) {
            return true;
        }

        public boolean isMsgReceived() {
            return msgReceived;
        }

        public String getMsgUrl() {
            return msgUrl;
        }
    }
}
