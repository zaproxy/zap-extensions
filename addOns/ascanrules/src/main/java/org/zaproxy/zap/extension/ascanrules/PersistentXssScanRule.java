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
package org.zaproxy.zap.extension.ascanrules;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.SourceSinkUtils;
import org.zaproxy.zap.extension.ascanrules.httputils.HtmlContext;
import org.zaproxy.zap.extension.ascanrules.httputils.HtmlContextAnalyser;

public class PersistentXssScanRule extends CrossSiteScriptingScanRule {

    /** Prefix for internationalised messages used by this rule */
    private static final String MESSAGE_PREFIX = "ascanrules.persistentxssattack.";

    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A03_INJECTION,
                    CommonAlertTag.OWASP_2017_A07_XSS,
                    CommonAlertTag.WSTG_V42_INPV_02_STORED_XSS);

    private static Logger log = LogManager.getLogger(PersistentXssScanRule.class);

    @Override
    public int getId() {
        return 40014;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String[] getDependency() {
        return new String[] {"PersistentXssSpiderScanRule"};
    }

    @Override
    public void scan(HttpMessage sourceMsg, String param, String value) {
        if (!AlertThreshold.LOW.equals(getAlertThreshold())
                && HttpRequestHeader.PUT.equals(sourceMsg.getRequestHeader().getMethod())) {
            return;
        }

        try {
            Set<Integer> sinks = SourceSinkUtils.getSinksIdsForSource(sourceMsg, param);

            if (sinks != null) {
                // Loop through each one

                // Inject the 'safe' eyecatcher
                setParameter(sourceMsg, param, Constant.getEyeCatcher());
                sendAndReceive(sourceMsg);

                // Check each sink
                for (Integer sinkMsgId : sinks) {
                    if (isStop()) {
                        break;
                    }

                    HttpMessage sinkMsg = SourceSinkUtils.getMessage(sinkMsgId);
                    if (sinkMsg == null) {
                        continue;
                    }

                    sinkMsg = sinkMsg.cloneRequest();
                    sendAndReceive(sinkMsg);

                    HtmlContextAnalyser hca = new HtmlContextAnalyser(sinkMsg);
                    List<HtmlContext> contexts =
                            hca.getHtmlContexts(Constant.getEyeCatcher(), null, 0);
                    boolean appendValue = false; // Check if somehow we can get this value on stored
                    testContexts(contexts, sourceMsg, sinkMsg, sinkMsg, appendValue, param, value);
                }
            }
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }
    }

    @Override
    public String adaptOtherInfo(String text) {
        return Constant.messages.getString(
                        MESSAGE_PREFIX + "otherinfo",
                        getBaseMsg().getRequestHeader().getURI().toString())
                + "\n"
                + text;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }
}
