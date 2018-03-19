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

package org.zaproxy.zap.extension.ascanrulesBeta;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.ProxyClient;
import org.apache.commons.httpclient.ProxyClient.ConnectResponse;
import org.apache.commons.httpclient.StatusLine;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang3.ArrayUtils;
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
 * a scanner that looks for known insecure HTTP methods enabled for the URL Note
 * that HTTP methods can be enabled for individual URLs, rather than necessarily
 * just at host level It is also possible for methods to be actually be
 * supported, without being documented by the OPTIONS method, so at High Attack
 * Strength, check that as well (regardless of Threshold).
 * 
 * @author 70pointer
 *
 */
public class InsecureHTTPMethod extends AbstractAppPlugin {

    /* WebDAV methods */
    private static final String COPY = "COPY";

    private static final String LOCK = "LOCK";

    private static final String MKCOL = "MKCOL";

    private static final String MOVE = "MOVE";

    private static final String PROPFIND = "PROPFIND";

    private static final String PROPPATCH = "PROPPATCH";

    private static final String UNLOCK = "UNLOCK";

    /* These are the 'default' HTTP methods which are considered as insecure */
    public static final String[] INSECURE_DEFAULT_METHODS = {
            /* Used by proxy server */
            HttpRequestHeader.CONNECT,
            /* This is almost never implemented by the server */
            HttpRequestHeader.DELETE,
            /*
             * Request for information about the communication options available
             */
            HttpRequestHeader.OPTIONS,
            /* Request for a change in a resource identified by the URI */
            // HttpRequestHeader.PATCH, // TODO wait for https://github.com/zaproxy/zaproxy/pull/3428
            /* For putting or updating a resource on the server */
            HttpRequestHeader.PUT,
            /* Mostly used for debugging purposes */
            HttpRequestHeader.TRACE,
            /* M$ version of TRACE */
            // HttpRequestHeader.TRACK // TODO wait for https://github.com/zaproxy/zaproxy/pull/3428
            };

    /* These are the WEBDAV methods bundled */
    public static final String[] WEBDAV_METHODS = {COPY, LOCK, MKCOL, MOVE, PROPFIND, PROPPATCH, UNLOCK};

    /**
     * The set of methods that we know are unsafe. It's a combination of the
     * 'default' HTTP methods and the WEBDAV methods.
     */
    public static final List<String> INSECURE_METHODS = new ArrayList<String>(Arrays.asList(ArrayUtils.addAll(INSECURE_DEFAULT_METHODS, WEBDAV_METHODS)));

    /**
     * details of the vulnerability which we are attempting to find 45 =
     * "Fingerprinting"
     */
    private static final Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_45");

    /**
     * the logger object
     */
    private static final Logger log = Logger.getLogger(InsecureHTTPMethod.class);

    /**
     * returns the plugin id
     */
    @Override
    public int getId() {

        return 90028;
    }

    /**
     * returns the name of the plugin
     */
    @Override
    public String getName() {

        return Constant.messages.getString("ascanbeta.insecurehttpmethod.name");
    }

    @Override
    public String[] getDependency() {

        return null;
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
    public void init() {

    }

    @Override
    public void scan() {

        /* Add the WEBDAV methods to the INSECURE methods */
        INSECURE_METHODS.addAll(new LinkedList<String>(Arrays.asList(WEBDAV_METHODS)));

        try {
            String allowedmethods = null;
            String publicmethods = null;
            String thirdpartyHost = "www.google.com";
            int thirdpartyPort = 80;
            Pattern thirdPartyContentPattern = Pattern.compile("<title.*Google.*/title>", Pattern.CASE_INSENSITIVE);

            AttackStrength attackStrength = getAttackStrength();
            if (attackStrength == AttackStrength.HIGH || attackStrength == AttackStrength.INSANE) {
                // in this case, we do not bother with the OPTIONS method, but
                // try all the insecure methods on the URL directly
                // this is useful in the case where the OPTIONS method does not
                // report the method, but where it is actually supported
                // in this case, if a vulnerability is reported, there is little
                // doubt that it is real
                // try the TRACK method
                MessageAndEvidence maeTrack = testTraceOrTrack(this.getBaseMsg(), "TRACK");
                if (maeTrack != null) {
                    bingo(Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, Constant.messages.getString("ascanbeta.insecurehttpmethod.detailed.name", "TRACK"),
                            Constant.messages.getString("ascanbeta.insecurehttpmethod.trace.exploitable.desc", "TRACK"), null, // originalMessage.getRequestHeader().getURI().getURI(),
                            null, // parameter being attacked: none.
                            "", // attack
                            Constant.messages.getString("ascanbeta.insecurehttpmethod.trace.exploitable.extrainfo", maeTrack.evidence),
                            Constant.messages.getString("ascanbeta.insecurehttpmethod.soln"), maeTrack.evidence, // evidence,
                                                                                                                 // highlighted
                                                                                                                 // in
                                                                                                                 // the
                                                                                                                 // message
                            maeTrack.message);
                }
                // try the TRACE method
                MessageAndEvidence maeTrace = testTraceOrTrack(this.getBaseMsg(), "TRACE");
                if (maeTrace != null) {
                    bingo(Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, Constant.messages.getString("ascanbeta.insecurehttpmethod.detailed.name", "TRACE"),
                            Constant.messages.getString("ascanbeta.insecurehttpmethod.trace.exploitable.desc", "TRACE"), null, // originalMessage.getRequestHeader().getURI().getURI(),
                            null, // parameter being attacked: none.
                            "", // attack
                            Constant.messages.getString("ascanbeta.insecurehttpmethod.trace.exploitable.extrainfo", maeTrace.evidence),
                            Constant.messages.getString("ascanbeta.insecurehttpmethod.soln"), maeTrace.evidence, // evidence,
                                                                                                                 // highlighted
                                                                                                                 // in
                                                                                                                 // the
                                                                                                                 // message
                            maeTrace.message);
                }

                // use a CONNECT method to try establish a socket connection to
                // a third party, via the server being tested
                boolean connectWorks = testConnect(this.getBaseMsg(), thirdpartyHost, thirdpartyPort, thirdPartyContentPattern);
                if (connectWorks) {
                    bingo(Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, Constant.messages.getString("ascanbeta.insecurehttpmethod.detailed.name", "CONNECT"),
                            Constant.messages.getString("ascanbeta.insecurehttpmethod.connect.exploitable.desc", "CONNECT"), null, // originalMessage.getRequestHeader().getURI().getURI(),
                            null, // parameter being attacked: none.
                            "", // attack
                            Constant.messages.getString("ascanbeta.insecurehttpmethod.connect.exploitable.extrainfo", thirdpartyHost),
                            Constant.messages.getString("ascanbeta.insecurehttpmethod.soln"), "", // evidence,
                                                                                                  // highlighted
                                                                                                  // in
                                                                                                  // the
                                                                                                  // message
                            this.getBaseMsg());
                }

                /* Test all other methods */
                for (String insecureMethod : INSECURE_METHODS) {
                    MessageAndEvidence mae = testHttpMethod(insecureMethod);
                    if (mae != null) {
                        DescriptionAndExtraInfo messages = getMessageForHttpMethod(insecureMethod);
                        bingo(Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM, Constant.messages.getString("ascanbeta.insecurehttpmethod.detailed.name", "CONNECT"),
                                Constant.messages.getString("ascanbeta.insecurehttpmethod.connect.exploitable.desc", "CONNECT"), null, // originalMessage.getRequestHeader().getURI().getURI(),
                                /* parameter being attacked: none */
                                null,                                
                                /* attack */
                                "",
                                /* description */
                                messages.description,
                                /* extra info */
                                messages.extraInfo, 
                                /* evidence, highlighted in the message */
                                "evidence",
                                this.getBaseMsg());
                    }
                }
            }

            if (attackStrength != AttackStrength.HIGH && attackStrength != AttackStrength.INSANE) {
                // send an OPTIONS message, and see what the server reports. Do
                // not try any methods not listed in those results.
                HttpMessage optionsmsg = getNewMsg();
                HttpRequestHeader optionsRequestHeader = this.getBaseMsg().getRequestHeader();
                optionsRequestHeader.setMethod(HttpRequestHeader.OPTIONS);
                optionsRequestHeader.setVersion(HttpRequestHeader.HTTP11); // OPTIONS
                                                                           // is
                                                                           // not
                                                                           // supported
                                                                           // in
                                                                           // 1.0
                optionsmsg.setRequestHeader(optionsRequestHeader);

                sendAndReceive(optionsmsg, false); // do not follow redirects

                allowedmethods = optionsmsg.getResponseHeader().getHeader(HttpHeader.METHODS_ALLOW);
                publicmethods = optionsmsg.getResponseHeader().getHeader(HttpHeader.METHODS_PUBLIC);

                /*
                 * //DEBUG only, to test the CONNECT method against a Squid
                 * instance, which does not support OPTIONS. //TODO: need to
                 * test for these insecure methods, even if the OPTIONS method
                 * did not indicate that the method is supported //ie, test for
                 * hidden/masked support for these insecure methods, as well as
                 * documented support.
                 * log.error("Setting the allowed methods to 'CONNECT'");
                 * allowedmethods = "CONNECT"; publicmethods = null;
                 */

                if (log.isDebugEnabled()) {
                    log.debug("allowedmethods: " + allowedmethods);
                    log.debug("publicmethods: " + publicmethods);
                }

                if (allowedmethods == null) {
                    // nothing to see here. Move along now.
                    return;
                }
                // if the "Public" response is present (for IIS), use that to
                // determine the enabled methods.
                if (publicmethods != null) {
                    allowedmethods = publicmethods;
                }

                // rely on the OPTIONS METHOD, but potentially verify the
                // results, depending on the Threshold.
                for (String enabledmethod : allowedmethods.toUpperCase().split(",")) {
                    enabledmethod = enabledmethod.trim(); // strip off any
                                                          // leading spaces (it
                                                          // happens!)

                    if (log.isDebugEnabled()) {
                        log.debug("The following enabled method is being checked: '" + enabledmethod + "'");
                    }

                    for (String insecureMethod : INSECURE_METHODS) {
                        if (enabledmethod.equals(insecureMethod)) {
                            String evidence = null;
                            HttpMessage alertMessage = optionsmsg;
                            String extraInfo = null;
                            String description = null;

                            // if the threshold is Medium or above, then we need
                            // to confirm the vulnerability before alerting
                            boolean raiseAlert = false;
                            AlertThreshold threshold = getAlertThreshold();
                            if (threshold != AlertThreshold.LOW) {
                                // != Low threshold --> verify it
                                if (enabledmethod.equals("CONNECT")) {

                                    log.debug("Verifying a CONNECT");

                                    // use a CONNECT method to establish a
                                    // socket connection to a third party, via
                                    // the server being tested
                                    boolean connectWorks = testConnect(this.getBaseMsg(), thirdpartyHost, thirdpartyPort, thirdPartyContentPattern);
                                    if (connectWorks) {
                                        raiseAlert = true;
                                        evidence = "";
                                        alertMessage = optionsmsg; // there is
                                                                   // no
                                                                   // connectmessage,
                                                                   // since the
                                                                   // HttpSender
                                                                   // does not
                                                                   // support
                                                                   // CONNECT
                                        description = Constant.messages.getString("ascanbeta.insecurehttpmethod.connect.exploitable.desc", enabledmethod);
                                        extraInfo = Constant.messages.getString("ascanbeta.insecurehttpmethod.connect.exploitable.extrainfo", thirdpartyHost);
                                    }

                                } else if (enabledmethod.equals("TRACE") || enabledmethod.equals("TRACK")) {

                                    log.debug("Verifying a TRACE/TRACK");
                                    MessageAndEvidence mae = testTraceOrTrack(this.getBaseMsg(), enabledmethod);
                                    if (mae != null) {
                                        raiseAlert = true;
                                        evidence = mae.evidence;
                                        alertMessage = mae.message;
                                        description = Constant.messages.getString("ascanbeta.insecurehttpmethod.trace.exploitable.desc", enabledmethod);
                                        extraInfo = Constant.messages.getString("ascanbeta.insecurehttpmethod.trace.exploitable.extrainfo", evidence);
                                    }
                                } else if (INSECURE_METHODS.contains(enabledmethod)) {
                                    MessageAndEvidence mae = testHttpMethod(enabledmethod);
                                    if (mae != null) {
                                        raiseAlert = true;
                                        DescriptionAndExtraInfo messages = getMessageForHttpMethod(enabledmethod);
                                        evidence = mae.evidence;
                                        alertMessage = mae.message;
                                        description = messages.description;
                                        extraInfo = messages.extraInfo;
                                    }
                                } else {
                                    throw new Exception("Cannot verify unrecognised HTTP method '" + enabledmethod + "'");
                                }

                            } else {
                                // == Low threshold --> no need to verify it
                                raiseAlert = true;
                                evidence = enabledmethod;
                                alertMessage = optionsmsg;
                                description = Constant.messages.getString("ascanbeta.insecurehttpmethod.desc", enabledmethod);
                                extraInfo = Constant.messages.getString("ascanbeta.insecurehttpmethod.extrainfo", allowedmethods);
                            }

                            if (raiseAlert) {
                                log.debug("Raising alert for Insecure HTTP Method");

                                // bingo.
                                bingo(Alert.RISK_MEDIUM, Alert.CONFIDENCE_MEDIUM,
                                        Constant.messages.getString("ascanbeta.insecurehttpmethod.detailed.name", insecureMethod), description, null, // originalMessage.getRequestHeader().getURI().getURI(),
                                        null, // parameter being attacked: none.
                                        "", // attack
                                        extraInfo, Constant.messages.getString("ascanbeta.insecurehttpmethod.soln"), evidence, // evidence,
                                                                                                                               // highlighted
                                                                                                                               // in
                                                                                                                               // the
                                                                                                                               // message
                                        alertMessage);
                            }
                        } else {
                            if (log.isDebugEnabled()) {
                                log.debug(enabledmethod + "!=" + insecureMethod);
                            }
                        }
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

    private class MessageAndEvidence {

        public HttpMessage message;

        public String evidence;

        public MessageAndEvidence(HttpMessage message, String evidence) {
            this.message = message;
            this.evidence = evidence;
        }
    }
    
    private class DescriptionAndExtraInfo {

        public String description;

        public String extraInfo;

        public DescriptionAndExtraInfo() {
        }

        @SuppressWarnings("unused")
        public DescriptionAndExtraInfo(String description, String extraInfo) {
            this.description = description;
            this.extraInfo = extraInfo;
        }
    }
    

    private MessageAndEvidence testTraceOrTrack(HttpMessage baseMsg, String method) throws Exception {

        HttpRequestHeader traceRequestHeader = baseMsg.getRequestHeader();
        traceRequestHeader.setMethod(method);
        // TRACE is supported in 1.0. TRACK is presumably the same, since it is
        // a alias for TRACE. Typical Microsoft.
        traceRequestHeader.setVersion(HttpRequestHeader.HTTP10);

        HttpMessage tracemsg = getNewMsg();
        tracemsg.setRequestHeader(traceRequestHeader);
        String randomcookiename = RandomStringUtils.random(15, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
        String randomcookievalue = RandomStringUtils.random(40, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
        TreeSet<HtmlParameter> cookies = tracemsg.getCookieParams();
        cookies.add(new HtmlParameter(HtmlParameter.Type.cookie, randomcookiename, randomcookievalue));
        tracemsg.setCookieParams(cookies);

        sendAndReceive(tracemsg, false); // do not follow redirects. That might
                                         // ruin our day.
        // if the response *body* from the TRACE request contains the cookie,
        // we're in business :)
        if (tracemsg.getResponseBody().toString().contains(randomcookievalue)) {
            return new MessageAndEvidence(tracemsg, randomcookievalue);
        }

        return null;
    }

    private boolean testConnect(HttpMessage baseMsg, String thirdpartyHost, int thirdpartyPort, Pattern thirdPartyContentPattern) throws Exception {

        String connecthost = baseMsg.getRequestHeader().getURI().getHost();
        int connectport = baseMsg.getRequestHeader().getURI().getPort();

        // this cannot currently be done using the existing HttpSender class, so
        // do it natively using HttpClient,
        // in as simple as possible a manner.
        Socket socket = null;
        try {
            ProxyClient client = new ProxyClient();
            client.getHostConfiguration().setProxy(connecthost, connectport);
            client.getHostConfiguration().setHost(thirdpartyHost, thirdpartyPort);
            ConnectResponse connectResponse = client.connect();
            StatusLine statusLine = connectResponse.getConnectMethod().getStatusLine();

            if (log.isDebugEnabled())
                log.debug("The status line returned: " + statusLine);

            int statusCode = statusLine.getStatusCode();
            socket = connectResponse.getSocket();
            if (socket != null && statusCode == HttpStatus.SC_OK) {
                // we have a socket and a 200 status.
                // Could still be a false positive though, if the server ignored
                // the method,
                // and did not recognise the URL, so redirected to a login page,
                // for instance
                // Remediation: Check the contents match the expected third
                // party contents.
                if (log.isDebugEnabled())
                    log.debug("Raw Socket established, in theory to " + thirdpartyHost);

                OutputStream os = socket.getOutputStream();
                InputStream is = socket.getInputStream();

                PrintWriter pw = new PrintWriter(os, false);
                pw.write("GET http://" + thirdpartyHost + ":" + thirdpartyPort + "/ HTTP/1.1\n");
                pw.write("Host: " + thirdpartyHost + "\n\n");
                pw.flush();

                // read the response via a 4k buffer
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024 * 4];
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
                    is.close();
                    os.close();
                    bos.close();
                    socket.close();
                    return true;
                } else {
                    log.debug("Response does *not* match expected third party pattern");
                }
                is.close();
                os.close();
                bos.close();
                socket.close();
                return false;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "Could not establish a socket connection to a third party using the CONNECT HTTP method: NULL socket returned, or non-200 response");
                    log.debug("The status line returned: " + statusLine);
                }
                return false;
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Could not establish a socket connection to a third party using the CONNECT HTTP method", e);
            }
        }
        return false;
    }

    private final MessageAndEvidence testHttpMethod(String httpMethod) {

        httpMethod = httpMethod.toLowerCase().trim();

        // TODO wait for https://github.com/zaproxy/zaproxy/pull/3428
        // TODO then use HttpRequestHeader.TRACK
        if (httpMethod.equals("TRACK") || httpMethod.equals(HttpRequestHeader.TRACE) || httpMethod.equals(HttpRequestHeader.CONNECT)) {
            /* We have separate methods for them */
            return null;
        }
        final HttpRequestHeader traceRequestHeader = this.getBaseMsg().getRequestHeader();

        traceRequestHeader.setMethod(httpMethod);
        traceRequestHeader.setVersion(HttpRequestHeader.HTTP11);

        final HttpMessage tracemsg = getNewMsg();
        tracemsg.setRequestHeader(traceRequestHeader);
        try {
            // do not follow redirects. That might ruin our day.
            sendAndReceive(tracemsg, false);
        } catch (IOException e) {
            log.error(e.getMessage(), e);
            return null;
        }

        MessageAndEvidence ret = null;

        final int responseCode = tracemsg.getResponseHeader().getStatusCode();

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

        if (responseCode == HttpStatusCode.OK) {
            ret = new MessageAndEvidence(tracemsg, "200 for insecure HTTP METHOD");
        } else if (enabledStatusCodes.contains(responseCode)) {
            /* Raise a reduced risk alert */

        }

        return ret;
    }

    private final DescriptionAndExtraInfo getMessageForHttpMethod(String httpMethod) {

        httpMethod = httpMethod.toLowerCase().trim();

        final DescriptionAndExtraInfo messages = new DescriptionAndExtraInfo();

        if (httpMethod.equals(HttpRequestHeader.DELETE)) {
            messages.description = Constant.messages.getString("ascanbeta.insecurehttpmethod.delete.exploitable.desc");
            messages.extraInfo = Constant.messages.getString("ascanbeta.insecurehttpmethod.delete.exploitable.extrainfo");
        }

        if (httpMethod.equals(HttpRequestHeader.OPTIONS)) {
            messages.description = Constant.messages.getString("ascanbeta.insecurehttpmethod.options.exploitable.desc");
            messages.extraInfo = Constant.messages.getString("ascanbeta.insecurehttpmethod.options.exploitable.extrainfo");
        }

        if (httpMethod.equals(HttpRequestHeader.PUT)) {
            messages.description = Constant.messages.getString("ascanbeta.insecurehttpmethod.put.exploitable.desc");
            messages.extraInfo = Constant.messages.getString("ascanbeta.insecurehttpmethod.put.exploitable.extrainfo");
        }

        if (Arrays.asList(WEBDAV_METHODS).contains(httpMethod)) {
            messages.description = Constant.messages.getString("ascanbeta.insecurehttpmethod.webdav.exploitable.desc");
            messages.extraInfo = Constant.messages.getString("ascanbeta.insecurehttpmethod.webdav.exploitable.extrainfo");
        }

        return messages;
    }
}