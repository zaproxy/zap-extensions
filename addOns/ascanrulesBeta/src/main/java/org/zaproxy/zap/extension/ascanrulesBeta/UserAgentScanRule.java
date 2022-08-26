/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;

/** @author kniepdennis@gmail.com */
public class UserAgentScanRule extends AbstractAppPlugin {

    private static final Logger log = LogManager.getLogger(UserAgentScanRule.class);

    private static final int PLUGIN_ID = 10104;
    private static final String MESSAGE_PREFIX = "ascanbeta.useragent.";
    private static final String USER_AGENT_PARAM_NAME =
            Constant.messages.getString(MESSAGE_PREFIX + "useragentparmname");

    private static final String INTERNET_EXPLORER_8 =
            "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)";
    private static final String INTERNET_EXPLORER_7 =
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)";
    private static final String INTERNET_EXPLORER_6 =
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)";
    // 2022-06-15 "Latest" IE UA according to:
    // https://www.whatismybrowser.com/guides/the-latest-user-agent/internet-explorer
    private static final String INTERNET_EXPLORER_11 =
            "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko";
    // First release of Edge Chromium, per: https://superuser.com/a/1552859
    private static final String EDGE_CHROMIUM =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3739.0 Safari/537.36 Edg/75.0.109.0";
    private static final String GOOGLE_BOT_2_1 =
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
    private static final String MSN_BOT_1_1 = "msnbot/1.1 (+http://search.msn.com/msnbot.htm)";
    private static final String YAHOO_SLURP =
            "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)";
    private static final String I_PHONE_3 =
            "Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Version/4.0 Mobile/7A341 Safari/528.16";
    // 2022-06-15 iPhone 6 is now EOL (https://endoflife.date/iphone), latest UA per:
    // https://www.quora.com/What-is-the-iPhone-6-and-iPhone-6-plus-user-agent
    private static final String I_PHONE_6 =
            "Mozilla/5.0 (iPhone; CPU iPhone OS 8_0_2 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12A366 Safari/600.1.4";
    // 2022-06-15 I looked up the ESR and it's currently 91, UA per:
    // https://whatmyuseragent.com/browser/ff/firefox/firefox-91
    private static final String FF_91_WIN10 =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/91.0";
    // 2022-16-15 I couldn't find a good source of EOL info for Chrome, so I'm going v91 like
    // Firefox, per:
    // https://developers.whatismybrowser.com/useragents/parse/86857789chrome-windows-blink
    private static final String CHROME_91_WIN10 =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";

    private static final List<String> USER_AGENTS =
            Arrays.asList(
                    INTERNET_EXPLORER_8,
                    INTERNET_EXPLORER_7,
                    INTERNET_EXPLORER_6,
                    INTERNET_EXPLORER_11,
                    EDGE_CHROMIUM,
                    GOOGLE_BOT_2_1,
                    MSN_BOT_1_1,
                    YAHOO_SLURP,
                    I_PHONE_3,
                    I_PHONE_6,
                    FF_91_WIN10,
                    CHROME_91_WIN10);

    private static final Supplier<Iterable<String>> DEFAULT_PAYLOAD_PROVIDER = () -> USER_AGENTS;
    public static final String USER_AGENT_PAYLOAD_CATEGORY = "User-Agent";

    private static Supplier<Iterable<String>> payloadProvider = DEFAULT_PAYLOAD_PROVIDER;

    private int originalResponseBodyHash;

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_INFO;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "desc");
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER;
    }

    @Override
    public String getSolution() {
        return "";
    }

    @Override
    public String getReference() {
        return Constant.messages.getString(MESSAGE_PREFIX + "refs");
    }

    @Override
    public void scan() {
        originalResponseBodyHash = getBaseMsg().getResponseBody().hashCode();

        for (String userAgentPayload : getUserAgentPayloads().get()) {
            if (isStop()) {
                return;
            }
            attack(userAgentPayload);
        }
    }

    public static void setPayloadProvider(Supplier<Iterable<String>> provider) {
        payloadProvider = provider == null ? DEFAULT_PAYLOAD_PROVIDER : provider;
    }

    private static Supplier<Iterable<String>> getUserAgentPayloads() {
        return payloadProvider;
    }

    public static List<String> getUserAgents() {
        return USER_AGENTS;
    }

    private void attack(String userAgent) {
        HttpMessage newMsg = sendUserAgent(userAgent);
        if (newMsg != null && isResponseDifferentFromOriginal(newMsg)) {
            createAlert(newMsg, userAgent);
        }
    }

    private HttpMessage sendUserAgent(String userAgent) {
        try {
            HttpMessage newMsg = getNewMsg();
            HttpRequestHeader header = newMsg.getRequestHeader();
            header.setHeader(HttpHeader.USER_AGENT, userAgent);
            sendAndReceive(newMsg);
            return newMsg;
        } catch (UnknownHostException | URIException e) {
            log.debug("Failed to send HTTP message, cause: {}", e.getMessage());
        } catch (IOException e) {
            log.warn(e.getMessage(), e);
        }
        return null;
    }

    private boolean isResponseDifferentFromOriginal(HttpMessage newMsg) {
        return isStatusCodeDifferent(newMsg) || isBodyDifferent(newMsg);
    }

    private boolean isStatusCodeDifferent(HttpMessage newMsg) {
        return getBaseMsg().getResponseHeader().getStatusCode()
                != newMsg.getResponseHeader().getStatusCode();
    }

    private boolean isBodyDifferent(HttpMessage newMsg) {
        return originalResponseBodyHash != newMsg.getResponseBody().hashCode();
    }

    private void createAlert(HttpMessage newMsg, String userAgent) {
        buildAlert(newMsg, userAgent).raise();
    }

    private AlertBuilder buildAlert(HttpMessage msg, String userAgent) {
        return newAlert()
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setParam(USER_AGENT_PARAM_NAME)
                .setAttack(userAgent)
                .setMessage(msg);
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();
        Alert example = buildAlert(null, "ExampleBot 1.1").build();
        example.setTags(
                CommonAlertTag.mergeTags(example.getTags(), CommonAlertTag.CUSTOM_PAYLOADS));
        alerts.add(example);
        return alerts;
    }
}
