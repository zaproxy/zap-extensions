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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.ProxyClient;
import org.apache.commons.httpclient.ProxyClient.ConnectResponse;
import org.apache.commons.httpclient.StatusLine;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * a scan rule that looks for known insecure HTTP methods enabled for the URL Note that HTTP methods
 * can be enabled for individual URLs, rather than necessarily just at host level It is also
 * possible for methods to be actually be supported, without being documented by the OPTIONS method,
 * so at High Attack Strength, check that as well (regardless of Threshold).
 *
 * @author 70pointer
 */
public class InsecureHttpMethodScanRule extends AbstractAppPlugin {

    /* These are the 'default' HTTP methods which are considered as insecure */
    private static final List<String> INSECURE_DEFAULT_METHODS =
            Arrays.asList(
                    /* Request for a change in a resource identified by the URI */
                    HttpRequestHeader.PATCH,
                    /* For putting or updating a resource on the server */
                    HttpRequestHeader.PUT);

    /* These are the WEBDAV methods bundled */
    private static final List<String> WEBDAV_METHODS =
            Arrays.asList("COPY", "LOCK", "MKCOL", "MOVE", "PROPFIND", "PROPPATCH", "UNLOCK");
    /** details of the vulnerability which we are attempting to find 45 = "Fingerprinting" */
    private static final Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_45");
    /** the logger object */
    private static final Logger log = Logger.getLogger(InsecureHttpMethodScanRule.class);
    /**
     * The set of methods that we know are unsafe. It's a combination of the 'default' HTTP methods
     * and the WEBDAV methods.
     */
    private static List<String> INSECURE_METHODS;

    static {
        INSECURE_METHODS = new ArrayList<String>();
        INSECURE_METHODS.addAll(INSECURE_DEFAULT_METHODS);
        INSECURE_METHODS.addAll(WEBDAV_METHODS);
    }

    @Override
    public int getId() {
        return 90028;
    }

    @Override
    public String getName() {
        return Constant.messages.getString("ascanbeta.insecurehttpmethod.name");
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
        return Category.SERVER;
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
            String thirdpartyHost = "www.google.com";
            int thirdpartyPort = 80;
            Pattern thirdPartyContentPattern =
                    Pattern.compile("<title.*Google.*/title>", Pattern.CASE_INSENSITIVE);

            // send an OPTIONS message, and see what the server reports. Do
            // not try any methods not listed in those results.
            HttpMessage optionsmsg = getNewMsg();
            HttpRequestHeader optionsRequestHeader = optionsmsg.getRequestHeader();
            optionsRequestHeader.setMethod(HttpRequestHeader.OPTIONS);
            // OPTIONS is not supported in 1.0
            optionsRequestHeader.setVersion(HttpRequestHeader.HTTP11);

            sendAndReceive(optionsmsg, false); // do not follow redirects

            String allowedmethods = getNonNullHeader(optionsmsg, HttpHeader.METHODS_ALLOW);
            String publicmethods = getNonNullHeader(optionsmsg, HttpHeader.METHODS_PUBLIC);

            /*
             * //DEBUG only, to test the CONNECT method against a Squid
             * instance, which does not support OPTIONS.
             * log.error("Setting the allowed methods to 'CONNECT'");
             * allowedmethods = "CONNECT"; publicmethods = null;
             */

            if (log.isDebugEnabled()) {
                log.debug("allowedmethods: " + allowedmethods);
                log.debug("publicmethods: " + publicmethods);
            }

            AttackStrength attackStrength = getAttackStrength();

            if (allowedmethods.isEmpty() && attackStrength == AttackStrength.MEDIUM
                    || attackStrength == AttackStrength.LOW) {
                // nothing to see here. Move along now.
                return;
            }
            // if the "Public" response is present (for IIS), use that to
            // determine the enabled methods.
            if (!publicmethods.isEmpty()) {
                allowedmethods += ", " + publicmethods;
            }

            // Convert the list to a set so that we have a unique list
            Set<String> enabledMethodsSet =
                    new HashSet<>(
                            Arrays.asList(allowedmethods.toUpperCase(Locale.ROOT).split(",")));
            if (enabledMethodsSet.contains(HttpRequestHeader.DELETE)) {
                enabledMethodsSet.remove(
                        HttpRequestHeader
                                .DELETE); // We don't actually want to make a DELETE request
                newAlert()
                        .setConfidence(Alert.CONFIDENCE_MEDIUM)
                        .setName(
                                Constant.messages.getString(
                                        "ascanbeta.insecurehttpmethod.detailed.name",
                                        HttpRequestHeader.DELETE))
                        .setDescription(
                                Constant.messages.getString(
                                        "ascanbeta.insecurehttpmethod.desc",
                                        HttpRequestHeader.DELETE))
                        .setOtherInfo(
                                Constant.messages.getString(
                                        "ascanbeta.insecurehttpmethod.extrainfo", allowedmethods))
                        .setSolution(
                                Constant.messages.getString("ascanbeta.insecurehttpmethod.soln"))
                        .setEvidence(HttpRequestHeader.DELETE)
                        .setMessage(optionsmsg)
                        .raise();
            }

            if (attackStrength == AttackStrength.HIGH || attackStrength == AttackStrength.INSANE) {
                // in this case, we do not bother with the OPTIONS method, but
                // try all the insecure methods on the URL directly
                // this is useful in the case where the OPTIONS method does not
                // report the method, but where it is actually supported
                // in this case, if a vulnerability is reported, there is little
                // doubt that it is real

                // try the TRACK method
                testTraceOrTrack(HttpRequestHeader.TRACK);
                // try the TRACE method
                testTraceOrTrack(HttpRequestHeader.TRACE);

                // use a CONNECT method to try establish a socket connection to
                // a third party, via the server being tested
                testConnect(
                        this.getBaseMsg(),
                        thirdpartyHost,
                        thirdpartyPort,
                        thirdPartyContentPattern);

                /* Test all other methods */
                for (String insecureMethod : INSECURE_METHODS) {
                    testHttpMethod(insecureMethod);
                }
            } else { // Not HIGH or INSANE
                // rely on the OPTIONS METHOD, but potentially verify the
                // results, depending on the Threshold.
                for (String enabledmethod : enabledMethodsSet) {
                    enabledmethod =
                            enabledmethod.trim(); // strip off any leading spaces (it happens!)
                    if (enabledmethod.isEmpty()) {
                        continue;
                    }

                    if (log.isDebugEnabled()) {
                        log.debug(
                                "The following enabled method is being checked: '"
                                        + enabledmethod
                                        + "'");
                    }
                    String insecureMethod = enabledmethod;

                    String evidence = null;
                    HttpMessage alertMessage = optionsmsg;
                    String extraInfo = null;
                    String description = null;
                    int riskLevel = Alert.RISK_INFO;
                    // if the threshold is Medium or above, then we need
                    // to confirm the vulnerability before alerting
                    boolean raiseAlert = false;
                    AlertThreshold threshold = getAlertThreshold();
                    if (threshold != AlertThreshold.LOW) {
                        // != Low threshold --> verify it
                        if (enabledmethod.equals(HttpRequestHeader.CONNECT)) {
                            log.debug("Verifying a CONNECT");
                            // use a CONNECT method to establish a
                            // socket connection to a third party, via
                            // the server being tested
                            testConnect(
                                    this.getBaseMsg(),
                                    thirdpartyHost,
                                    thirdpartyPort,
                                    thirdPartyContentPattern);

                        } else if (enabledmethod.equals(HttpRequestHeader.TRACE)
                                || enabledmethod.equals(HttpRequestHeader.TRACK)) {
                            log.debug("Verifying a TRACE/TRACK");
                            testTraceOrTrack(enabledmethod);
                        } else if (INSECURE_METHODS.contains(enabledmethod)) {
                            testHttpMethod(enabledmethod);

                        } else {
                            log.debug("Untested method: " + enabledmethod);
                        }

                    } else {
                        // == Low threshold --> no need to verify it
                        if (!WEBDAV_METHODS.contains(enabledmethod)) {
                            riskLevel = Alert.RISK_MEDIUM;
                        }
                        raiseAlert = true;
                        evidence = enabledmethod;
                        alertMessage = optionsmsg;
                        description =
                                Constant.messages.getString(
                                        "ascanbeta.insecurehttpmethod.desc", enabledmethod);
                        extraInfo =
                                Constant.messages.getString(
                                        "ascanbeta.insecurehttpmethod.extrainfo", allowedmethods);
                    }

                    if (raiseAlert) {
                        log.debug("Raising alert for Insecure HTTP Method");

                        newAlert()
                                .setRisk(riskLevel)
                                .setConfidence(Alert.CONFIDENCE_MEDIUM)
                                .setName(
                                        Constant.messages.getString(
                                                "ascanbeta.insecurehttpmethod.detailed.name",
                                                insecureMethod))
                                .setDescription(description)
                                .setOtherInfo(extraInfo)
                                .setSolution(
                                        Constant.messages.getString(
                                                "ascanbeta.insecurehttpmethod.soln"))
                                .setEvidence(evidence)
                                .setMessage(alertMessage)
                                .raise();
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error scanning a Host for Insecure HTTP Methods: " + e.getMessage(), e);
        }
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public int getCweId() {
        return 200; // Information Exposure (primarily via TRACK / TRACE)
    }

    @Override
    public int getWascId() {
        return 45; // Fingerprinting
    }

    private static String getNonNullHeader(HttpMessage msg, String headerName) {
        String headerValue = msg.getResponseHeader().getHeader(headerName);
        if (StringUtils.isBlank(headerValue)) {
            return "";
        }
        return headerValue;
    }

    private void testTraceOrTrack(String method) throws Exception {

        HttpMessage msg = getNewMsg();
        msg.getRequestHeader().setMethod(method);
        // TRACE is supported in 1.0. TRACK is presumably the same, since it is
        // a alias for TRACE. Typical Microsoft.
        msg.getRequestHeader().setVersion(HttpRequestHeader.HTTP10);
        String randomcookiename =
                RandomStringUtils.random(
                        15, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
        String randomcookievalue =
                RandomStringUtils.random(
                        40, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
        TreeSet<HtmlParameter> cookies = msg.getCookieParams();
        cookies.add(
                new HtmlParameter(HtmlParameter.Type.cookie, randomcookiename, randomcookievalue));
        msg.setCookieParams(cookies);
        // do not follow redirects. That might ruin our day.
        sendAndReceive(msg, false);

        // if the response *body* from the TRACE request contains the cookie,we're in business :)
        if (msg.getResponseBody().toString().contains(randomcookievalue)) {
            newAlert()
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setName(
                            Constant.messages.getString(
                                    "ascanbeta.insecurehttpmethod.detailed.name", method))
                    .setDescription(
                            Constant.messages.getString(
                                    "ascanbeta.insecurehttpmethod.trace.exploitable.desc", method))
                    .setUri(msg.getRequestHeader().getURI().getURI())
                    .setOtherInfo(
                            Constant.messages.getString(
                                    "ascanbeta.insecurehttpmethod.trace.exploitable.extrainfo",
                                    randomcookievalue))
                    .setSolution(Constant.messages.getString("ascanbeta.insecurehttpmethod.soln"))
                    .setEvidence(randomcookievalue)
                    .setMessage(msg)
                    .raise();
        }
    }

    private void testConnect(
            HttpMessage baseMsg,
            String thirdpartyHost,
            int thirdpartyPort,
            Pattern thirdPartyContentPattern)
            throws Exception {

        String connecthost = baseMsg.getRequestHeader().getURI().getHost();
        int connectport = baseMsg.getRequestHeader().getURI().getPort();

        // this cannot currently be done using the existing HttpSender class, so
        // do it natively using HttpClient,
        // in as simple as possible a manner.
        ByteArrayOutputStream bos = null;
        ProxyClient client = new ProxyClient();
        ConnectResponse connectResponse = null;
        client.getHostConfiguration().setProxy(connecthost, connectport);
        client.getHostConfiguration().setHost(thirdpartyHost, thirdpartyPort);
        try {
            connectResponse = client.connect();
        } catch (IOException ex) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "Could not establish a client connection to a third party using the CONNECT HTTP method",
                        ex);
            }
            return;
        }

        Socket socket = connectResponse.getSocket();
        if (socket == null) {
            return;
        }
        try (OutputStream os = socket.getOutputStream();
                InputStream is = socket.getInputStream()) {

            StatusLine statusLine = connectResponse.getConnectMethod().getStatusLine();

            if (log.isDebugEnabled()) log.debug("The status line returned: " + statusLine);

            int statusCode = statusLine.getStatusCode();

            if (statusCode == HttpStatus.SC_OK) {
                // we have a socket and a 200 status.
                // Could still be a false positive though, if the server ignored
                // the method,
                // and did not recognise the URL, so redirected to a login page,
                // for instance
                // Remediation: Check the contents match the expected third
                // party contents.
                if (log.isDebugEnabled())
                    log.debug("Raw Socket established, in theory to " + thirdpartyHost);

                PrintWriter pw = new PrintWriter(os, false);
                pw.write("GET http://" + thirdpartyHost + ":" + thirdpartyPort + "/ HTTP/1.1\n");
                pw.write("Host: " + thirdpartyHost + "\n\n");
                pw.flush();
                pw.close();

                // read the response via a 4k buffer
                bos = new ByteArrayOutputStream();
                byte[] buffer = new byte[4096];
                int bytesRead = is.read(buffer);
                int totalBytesRead = 0;
                while (bytesRead > -1) {
                    totalBytesRead += bytesRead;
                    bos.write(buffer, 0, bytesRead);
                    bytesRead = is.read(buffer);
                }
                String response = new String(bos.toByteArray());
                if (log.isDebugEnabled())
                    log.debug("Response is " + totalBytesRead + " bytes: \n" + response);

                Matcher m = thirdPartyContentPattern.matcher(response);
                if (m.matches()) {
                    log.debug("Response matches expected third party pattern!");
                    newAlert()
                            .setConfidence(Alert.CONFIDENCE_MEDIUM)
                            .setName(
                                    Constant.messages.getString(
                                            "ascanbeta.insecurehttpmethod.detailed.name",
                                            HttpRequestHeader.CONNECT))
                            .setDescription(
                                    Constant.messages.getString(
                                            "ascanbeta.insecurehttpmethod.connect.exploitable.desc",
                                            HttpRequestHeader.CONNECT))
                            .setOtherInfo(
                                    Constant.messages.getString(
                                            "ascanbeta.insecurehttpmethod.connect.exploitable.extrainfo",
                                            thirdpartyHost))
                            .setSolution(
                                    Constant.messages.getString(
                                            "ascanbeta.insecurehttpmethod.soln"))
                            .setEvidence(response)
                            .setMessage(this.getBaseMsg())
                            .raise();
                    return;
                } else {
                    log.debug("Response does *not* match expected third party pattern");
                }

            } else {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "Could not establish a socket connection to a third party using the CONNECT HTTP method: NULL socket returned, or non-200 response");
                    log.debug("The status line returned: " + statusLine);
                }
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "Could not establish a socket connection to a third party using the CONNECT HTTP method",
                        e);
            }
        } finally {
            socket.close();
        }
    }

    private void testHttpMethod(String httpMethod) throws Exception {

        final HttpMessage msg = getNewMsg();
        msg.getRequestHeader().setMethod(httpMethod);
        msg.getRequestHeader().setVersion(HttpRequestHeader.HTTP11);

        if (httpMethod.equals(HttpRequestHeader.PUT)
                || httpMethod.equals(HttpRequestHeader.PATCH)) {
            String randomKey =
                    RandomStringUtils.random(
                            15, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
            String randomValue =
                    RandomStringUtils.random(
                            15, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
            String randomResource =
                    RandomStringUtils.random(10, "abcdefghijklmnopqrstuvwxyz0123456789");
            String requestBody = '"' + randomKey + "\":\"" + randomValue + '"';
            String newURI = msg.getRequestHeader().getURI().getURI();
            if (newURI.endsWith("/")) {
                newURI += randomResource;
            } else {
                newURI += '/' + randomResource;
            }

            msg.getRequestHeader().setURI(new URI(newURI, false, URI.getDefaultProtocolCharset()));
            msg.setRequestBody(requestBody);
        }

        try {
            // do not follow redirects. That might ruin our day.
            sendAndReceive(msg, false);
        } catch (IOException e) {
            log.debug(e.getMessage(), e);
            return;
        }

        final int responseCode = msg.getResponseHeader().getStatusCode();
        String evidence = "";

        /*
         * Build a list with status code which indicate that this HTTP method is
         * enabled but we are not allowed to use it
         */
        final ArrayList<Integer> enabledStatusCodes = new ArrayList<>();
        enabledStatusCodes.add(HttpStatusCode.UNAUTHORIZED);
        enabledStatusCodes.add(HttpStatusCode.PAYMENT_REQUIRED);
        enabledStatusCodes.add(HttpStatusCode.FORBIDDEN);

        if (log.isDebugEnabled()) {
            log.debug("Request Method: " + httpMethod);
            log.debug("Response Code: " + responseCode);
        }

        if (responseCode == HttpStatusCode.OK || responseCode == HttpStatusCode.CREATED) {
            evidence =
                    Constant.messages.getString(
                            "ascanbeta.insecurehttpmethod.insecure", responseCode);
        } else if (enabledStatusCodes.contains(responseCode)) {
            evidence =
                    Constant.messages.getString(
                            "ascanbeta.insecurehttpmethod.potentiallyinsecure", responseCode);
        } else {
            return;
        }

        int riskLevel;
        String exploitableDesc;
        String exploitableExtraInfo;
        if (WEBDAV_METHODS.contains(httpMethod)) {
            exploitableDesc =
                    Constant.messages.getString(
                            "ascanbeta.insecurehttpmethod.webdav.exploitable.desc", httpMethod);
            exploitableExtraInfo =
                    Constant.messages.getString(
                            "ascanbeta.insecurehttpmethod.webdav.exploitable.extrainfo");
            riskLevel = Alert.RISK_INFO;
        } else {
            exploitableDesc =
                    Constant.messages.getString(
                            "ascanbeta.insecurehttpmethod."
                                    + httpMethod.toLowerCase()
                                    + ".exploitable.desc",
                            httpMethod);
            exploitableExtraInfo =
                    Constant.messages.getString(
                            "ascanbeta.insecurehttpmethod."
                                    + httpMethod.toLowerCase()
                                    + ".exploitable.extrainfo");

            riskLevel = Alert.RISK_MEDIUM;
        }
        try {

            newAlert()
                    .setRisk(riskLevel)
                    .setConfidence(Alert.CONFIDENCE_MEDIUM)
                    .setName(
                            Constant.messages.getString(
                                    "ascanbeta.insecurehttpmethod.detailed.name", httpMethod))
                    .setDescription(exploitableDesc)
                    .setOtherInfo(exploitableExtraInfo)
                    .setEvidence(evidence)
                    .setMessage(msg)
                    .raise();
        } catch (Exception e) {
        }
    }
}
