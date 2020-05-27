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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.net.UnknownHostException;
import java.util.List;
import java.util.Random;
import org.apache.commons.httpclient.InvalidRedirectLocationException;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.httputils.HtmlContext;
import org.zaproxy.zap.httputils.HtmlContextAnalyser;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * An example active scan rule, for more details see
 * http://zaproxy.blogspot.co.uk/2014/04/hacking-zap-4-active-scan-rules.html
 *
 * @author psiinon
 */
public class ExampleSimpleActiveScanner extends AbstractAppParamPlugin {
    public static final String NULL_BYTE_CHARACTER = String.valueOf((char) 0);
    // wasc_10 is Denial of Service - well, its just an example ;)
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_14");

    private Random rnd = new Random();

    private static Logger log = Logger.getLogger(ExampleSimpleActiveScanner.class);

    @Override
    public int getId() {
        /*
         * This should be unique across all active and passive rules.
         * The master list is https://github.com/zaproxy/zaproxy/blob/develop/docs/scanners.md
         */
        return 60100;
    }

    @Override
    public String getName() {
        // Strip off the "Example Active Scanner: " part if implementing a real one ;)
        if (vuln != null) {
            return "Example Active Scanner: " + vuln.getAlert();
        }
        return "Example Active Scanner: Denial of Service";
    }

    @Override
    public boolean targets(
            TechSet technologies) { // This method allows the programmer or user to restrict when a
        // scanner is run based on the technologies selected.  For example, to restrict the scanner
        // to run just when
        // C language is selected
        return technologies.includes(Tech.C);
    }

    @Override
    public String getDescription() {
        if (vuln != null) {
            return vuln.getDescription();
        }
        return "Failed to load vulnerability description from file";
    }

    @Override
    public int getCategory() {
        return Category.MISC;
    }

    @Override
    public String getSolution() {
        if (vuln != null) {
            return vuln.getSolution();
        }
        return "Failed to load vulnerability solution from file";
    }

    @Override
    public String getReference() {
        if (vuln != null) {
            StringBuilder sb = new StringBuilder();
            for (String ref : vuln.getReferences()) {
                if (sb.length() > 0) {
                    sb.append("\n");
                }
                sb.append(ref);
            }
            return sb.toString();
        }
        return "Failed to load vulnerability reference from file";
    }

    /*
     * This method is called by the active scanner for each GET and POST parameter for every page
     * @see org.parosproxy.paros.core.scanner.AbstractAppParamPlugin#scan(org.parosproxy.paros.network.HttpMessage, java.lang.String, java.lang.String)
     */

    public String generateAttackPayload() {
        // byte[] defaultPayload = "34234df<script>alert(1234)</script>dfsdf".getBytes();
        String[] prefix = {
            "", "<%<!--'%>", "sdfdsfg", "-->", "</svg>", "//", ">", "--><!-- --->", "--><!-- -->"
        };
        String scriptString = "<script>alert(1234)</script>";
        String[] suffix = {"", "sdfdsg"};
        String attackPayload =
                new StringBuilder()
                        .append(prefix[new Random().nextInt(prefix.length)])
                        .append(scriptString)
                        .append(suffix[new Random().nextInt(suffix.length)])
                        .toString();
        return attackPayload;
    }

    private List<HtmlContext> performAttack(
            HttpMessage msg,
            String param,
            String attack,
            HtmlContext targetContext,
            int ignoreFlags,
            boolean findDecoded,
            boolean isNullByteSpecialHandling) {
        if (isStop()) {
            return null;
        }

        HttpMessage msg2 = msg.cloneRequest();
        setParameter(msg2, param, attack);
        try {
            sendAndReceive(msg2);
        } catch (URIException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to send HTTP message, cause: " + e.getMessage());
            }
            return null;
        } catch (InvalidRedirectLocationException | UnknownHostException e) {
            // Not an error, just means we probably attacked the redirect
            // location
            return null;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

        if (isStop()) {
            return null;
        }
        if (isNullByteSpecialHandling) {
            /* Special handling for case where Attack Vector is reflected outside of html tag.
             * Removing Null Byte as parser tries to find the enclosing tag on attack vector (e.g.
             * \0<script>alert(1);</script>) starting from first character
             * and as null byte is not starting any tag and there is no enclosing tag for null byte
             * so parent context is null.
             */
            attack = attack.replaceFirst(NULL_BYTE_CHARACTER, "");
        }
        HtmlContextAnalyser hca = new HtmlContextAnalyser(msg2);
        if (Plugin.AlertThreshold.HIGH.equals(this.getAlertThreshold())) {
            // High level, so check all results are in the expected context
            return hca.getHtmlContexts(
                    findDecoded ? getURLDecode(attack) : attack, targetContext, ignoreFlags);
        }

        return hca.getHtmlContexts(findDecoded ? getURLDecode(attack) : attack);
    }

    @Override
    public void scan(HttpMessage msg, String param, String value) {

        // if (!Constant.isDevBuild()) {
        // Only run this example scanner in dev mode
        // Uncomment locally if you want to see these alerts in non dev mode ;)
        //  return;
        // }
        // This is where you change the 'good' request to attack the application
        // You can make multiple requests if needed
        // String attack = "attack";
        boolean attackWorked = false;
        int times = 0;
        while (!attackWorked && times < 5) {
            String attackString = generateAttackPayload();
            // Always use getNewMsg() for each new request
            /*msg = getNewMsg();
            setParameter(msg, param, attackString);
            sendAndReceive(msg);*/

            // This is where you detect potential vulnerabilities in the response
            List<HtmlContext> contexts =
                    performAttack(msg, param, attackString, null, 0, false, false);
            String GREP_STRING = "alert(1234)";
            /*HtmlContextAnalyser hca = new HtmlContextAnalyser(msg);
            List<HtmlContext> contexts = hca.getHtmlContexts(GREP_STRING, null, 0);*/
            if (contexts.size() > 0) {
                /*bingo(
                int risk,
                int confidence,
                String name,
                String description,
                String uri,
                String param,
                String attack,
                String otherInfo,
                String solution,
                HttpMessage msg);*/
                bingo(
                        Alert.RISK_HIGH,
                        Alert.CONFIDENCE_MEDIUM,
                        "Extension-XSS",
                        "XSS found by extension",
                        null,
                        param,
                        contexts.get(0).getTarget(),
                        contexts.get(0).getTarget(),
                        "XSS found by extension",
                        contexts.get(0).getMsg());
                // bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, null, param, value,
                // "Extension-XSS", msg);
                attackWorked = true;
            }
            times++;
        }
        // For this example we're just going to raise the alert at random!
        // if (rnd.nextInt(10) == 0) {
        //     bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, null, param, value,
        // "Extension-XSS", msg);
        //      return;
        //

    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        // The CWE id
        return 0;
    }

    @Override
    public int getWascId() {
        // The WASC ID
        return 0;
    }
}
