/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2011 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrules;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.htmlparser.jericho.Source;
import org.apache.commons.collections.iterators.IteratorChain;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.CookieUtils;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class CookieSecureFlagScanRule extends PluginPassiveScanner
        implements CommonPassiveScanRuleInfo {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "pscanrules.cookiesecureflag.";

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                                CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                                CommonAlertTag.WSTG_V42_SESS_02_COOKIE_ATTRS));
        alertTags.put(PolicyTag.PENTEST.getTag(), "");
        alertTags.put(PolicyTag.DEV_STD.getTag(), "");
        alertTags.put(PolicyTag.QA_STD.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private static final int PLUGIN_ID = 10011;

    private static final String SECURE_COOKIE_ATTRIBUTE = "Secure";

    private Model model = null;

    @Override
    public void scanHttpResponseReceive(HttpMessage msg, int id, Source source) {
        if (!msg.getRequestHeader().isSecure()) {
            // If SSL isn't used then the Secure flag has not to be checked
            return;
        }

        IteratorChain iterator = new IteratorChain();
        List<String> cookies1 = msg.getResponseHeader().getHeaderValues(HttpHeader.SET_COOKIE);

        if (!cookies1.isEmpty()) {
            iterator.addIterator(cookies1.iterator());
        }

        List<String> cookies2 = msg.getResponseHeader().getHeaderValues(HttpHeader.SET_COOKIE2);

        if (!cookies2.isEmpty()) {
            iterator.addIterator(cookies2.iterator());
        }

        Set<String> ignoreList = CookieUtils.getCookieIgnoreList(getModel());

        while (iterator.hasNext()) {
            String headerValue = (String) iterator.next();
            if (!CookieUtils.hasAttribute(headerValue, SECURE_COOKIE_ATTRIBUTE)) {
                if (CookieUtils.isExpired(headerValue)) {
                    continue;
                }
                if (!ignoreList.contains(CookieUtils.getCookieName(headerValue))) {
                    this.buildAlert(msg, headerValue).raise();
                }
            }
        }
    }

    private AlertBuilder buildAlert(HttpMessage msg, String headerValue) {
        return newAlert()
                .setRisk(Alert.RISK_LOW)
                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                .setDescription(Constant.messages.getString(MESSAGE_PREFIX + "desc"))
                .setParam(CookieUtils.getCookieName(headerValue))
                .setSolution(Constant.messages.getString(MESSAGE_PREFIX + "soln"))
                .setReference(Constant.messages.getString(MESSAGE_PREFIX + "refs"))
                .setEvidence(
                        CookieUtils.getSetCookiePlusName(
                                msg.getResponseHeader().toString(), headerValue))
                .setCweId(614) // CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure'
                // Attribute
                .setWascId(13); // WASC-13: Info leakage;
    }

    @Override
    public int getPluginId() {
        return PLUGIN_ID;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    private Model getModel() {
        if (this.model == null) {
            this.model = Model.getSingleton();
        }
        return this.model;
    }

    /*
     * Just for use in the unit tests
     */
    protected void setModel(Model model) {
        this.model = model;
    }

    @Override
    public List<Alert> getExampleAlerts() {
        List<Alert> alerts = new ArrayList<>();
        alerts.add(buildAlert(new HttpMessage(), "").build());
        return alerts;
    }
}
