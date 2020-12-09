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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * a scan rule that looks for, and exploits CVE-2012-1823 to disclose PHP application source code
 *
 * @author 70pointer
 */
public class SourceCodeDisclosureCve20121823ScanRule extends AbstractAppPlugin {

    /** match on PHP tags in the response */
    private static final Pattern PHP_PATTERN1 =
            Pattern.compile(
                    ".*(<\\?php.+?\\?>).*",
                    Pattern.MULTILINE | Pattern.DOTALL); // PHP standard tags

    private static final Pattern PHP_PATTERN2 =
            Pattern.compile(
                    ".*(<\\?=.+?\\?>).*",
                    Pattern.MULTILINE | Pattern.DOTALL); // PHP "echo short tag"

    /**
     * details of the vulnerability which we are attempting to find WASC 20 = Improper Input
     * Handling
     */
    private static final Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_20");

    private static final Logger log =
            Logger.getLogger(SourceCodeDisclosureCve20121823ScanRule.class);

    @Override
    public int getId() {
        return 20017;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.sourcecodedisclosurecve-2012-1823.name");
    }

    @Override
    public boolean targets(TechSet technologies) {
        if (technologies.includes(Tech.PHP)) {
            return true;
        }
        return false;
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
        return Category.INFO_GATHER;
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
                    sb.append('\n');
                }
                sb.append(ref);
            }
            return sb.toString();
        }
        return "Failed to load vulnerability reference from file";
    }

    @Override
    public void scan() {
        try {

            if (!getBaseMsg().getResponseHeader().isText()) {
                return; // Ignore images, pdfs, etc.
            }
            if (getAlertThreshold() != AlertThreshold.LOW
                    && getBaseMsg().getResponseHeader().isJavaScript()) {
                return;
            }
            // at Low or Medium strength, do not attack URLs which returned "Not Found"
            AttackStrength attackStrength = getAttackStrength();
            if ((attackStrength == AttackStrength.LOW || attackStrength == AttackStrength.MEDIUM)
                    && (isPage404(getBaseMsg()))) return;

            URI originalURI = getBaseMsg().getRequestHeader().getURI();

            // construct a new URL based on the original URL, but without any of the original
            // parameters
            String attackParam = "?-s";
            URI attackURI = createAttackUri(originalURI, attackParam);
            if (attackURI == null) {
                return;
            }
            // and send it as a GET, unauthorised.
            HttpMessage attackmsg = new HttpMessage(attackURI);
            sendAndReceive(attackmsg, false); // do not follow redirects

            if (isPage200(attackmsg)) {
                // double-check: does the response contain HTML encoded PHP?
                // Ignore the case where it contains encoded HTML for now, since thats not a source
                // code disclosure anyway
                // (HTML is always sent back to the web browser)
                String responseBody = new String(attackmsg.getResponseBody().getBytes());
                String responseBodyDecoded = new Source(responseBody).getRenderer().toString();

                Matcher matcher1 = PHP_PATTERN1.matcher(responseBodyDecoded);
                Matcher matcher2 = PHP_PATTERN2.matcher(responseBodyDecoded);
                boolean match1 = matcher1.matches();
                boolean match2 = matcher2.matches();

                if ((!responseBody.equals(responseBodyDecoded)) && (match1 || match2)) {

                    if (log.isDebugEnabled()) {
                        log.debug("Source Code Disclosure alert for: " + originalURI.getURI());
                    }

                    String sourceCode = null;
                    if (match1) {
                        sourceCode = matcher1.group(1);
                    } else {
                        sourceCode = matcher2.group(1);
                    }

                    // bingo.
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setDescription(
                                    Constant.messages.getString(
                                            "ascanbeta.sourcecodedisclosurecve-2012-1823.desc"))
                            .setOtherInfo(sourceCode)
                            .setSolution(
                                    Constant.messages.getString(
                                            "ascanbeta.sourcecodedisclosurecve-2012-1823.soln"))
                            .setMessage(attackmsg)
                            .raise();
                }
            }
        } catch (Exception e) {
            log.error(
                    "Error scanning a Host for Source Code Disclosure via CVE-2012-1823: "
                            + e.getMessage(),
                    e);
        }
    }

    private static URI createAttackUri(URI originalURI, String attackParam) {
        StringBuilder strBuilder = new StringBuilder();
        strBuilder
                .append(originalURI.getScheme())
                .append("://")
                .append(originalURI.getEscapedAuthority());
        strBuilder
                .append(originalURI.getRawPath() != null ? originalURI.getEscapedPath() : "/")
                .append(attackParam);
        String uri = strBuilder.toString();
        try {
            return new URI(uri, true);
        } catch (URIException e) {
            log.warn("Failed to create attack URI [" + uri + "], cause: " + e.getMessage());
        }
        return null;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }

    @Override
    public int getCweId() {
        return 20; // Improper Input Validation
    }

    @Override
    public int getWascId() {
        return 20; // Improper Input Handling
    }
}
