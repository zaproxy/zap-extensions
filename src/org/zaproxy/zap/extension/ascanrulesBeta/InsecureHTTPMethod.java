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
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.ProxyClient;
import org.apache.commons.httpclient.ProxyClient.ConnectResponse;
import org.apache.commons.httpclient.StatusLine;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * a scanner that looks for known insecure HTTP methods enabled for the URL Note that HTTP methods can be enabled for individual
 * URLs, rather than necessarily just at host level It is also possible for methods to be actually be supported, without being
 * documented by the OPTIONS method, so at High Attack Strength, check that as well (regardless of Threshold).
 * 
 * @author 70pointer
 * @author Rainer Hihn
 *
 */
public class InsecureHTTPMethod extends AbstractAppPlugin {

    private final String thirdpartyHost = "www.google.com";

    private final int thirdpartyPort = 80;

    private final Pattern thirdPartyContentPattern = Pattern.compile("<title.*Google.*/title>", Pattern.CASE_INSENSITIVE);

    /**
     * Names of all (insecure) http methods used in this rule
     */
    private static final String HTTP_METHOD_TRACE = "TRACE";

    private static final String HTTP_METHOD_TRACK = "TRACK";

    private static final String HTTP_METHOD_CONNECT = "CONNECT";

    private static final String HTTP_METHOD_PUT = "PUT";

    private static final String HTTP_METHOD_DELETE = "DELETE";

    private final ArrayList<String> checkedHosts = new ArrayList<>();

    /**
     * the set of methods that we know are unsafe. There may be others.
     */
    public static final List<String> INSECURE_METHODS = new ArrayList<String>(
            Arrays.asList(
                    new String[] {
                            HTTP_METHOD_TRACE,
                            HTTP_METHOD_TRACK,
                            HTTP_METHOD_CONNECT,
                            HTTP_METHOD_PUT,
                            HTTP_METHOD_DELETE }));

    /**
     * details of the vulnerability which we are attempting to find 45 = "Fingerprinting"
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

        final String requestHostname = this.getBaseMsg().getRequestHeader().getHostName();

        if (checkedHosts.contains(requestHostname)) {
            // We don't need to perform this check on every request -> performance
            log.debug("We already checked the hostname: " + requestHostname + " quitting.");
            return;
        }

        checkedHosts.add(requestHostname);

        try {
            final Mode mode = Control.getSingleton().getMode();
            if (mode.equals(Mode.safe) || mode.equals(Mode.protect)) {
                checkAllowedHttpMethods();
            } else {
                checkInsecureHttpMethods();
            }
        } catch (Exception e) {
            log.error("Error scanning a Host for Insecure HTTP Methods: " + e.getMessage(), e);
        }
    }

    /**
     * Send an OPTIONS message to the server and see what HTTP method it supports. Then check if there is a HTTP method among
     * them which is considered unsafe.
     * 
     * @throws Exception
     */
    private void checkAllowedHttpMethods() throws Exception {
        final HttpMessage optionsmsg = getNewMsg();
        final HttpRequestHeader optionsRequestHeader = this.getBaseMsg().getRequestHeader();
        optionsRequestHeader.setMethod(HttpRequestHeader.OPTIONS);
        optionsRequestHeader.setVersion(HttpRequestHeader.HTTP11);
        optionsmsg.setRequestHeader(optionsRequestHeader);
        sendAndReceive(optionsmsg, false); // do not follow redirects
        String allowedmethods = optionsmsg.getResponseHeader().getHeader("Allow");
        String publicmethods = optionsmsg.getResponseHeader().getHeader("Public");
        log.debug("allowedmethods: " + allowedmethods);
        log.debug("publicmethods: " + publicmethods);
        if (allowedmethods == null) {
            // nothing to see here. Move along now.
            return;
        }
        if (publicmethods != null) {
            // if the "Public" response is present (for IIS), use that to determine the enabled methods.
            allowedmethods = publicmethods;
        }
        // rely on the OPTIONS METHOD, but potentially verify the results, depending on the Threshold.
        for (String enabledmethod : allowedmethods.toUpperCase().split(",")) {
            enabledmethod = enabledmethod.trim(); // strip off any leading spaces (it happens!)
            log.debug("The following enabled method is being checked: '" + enabledmethod + "'");
            for (String insecureMethod : INSECURE_METHODS) {
                if (enabledmethod.equals(insecureMethod)) {
                    String evidence = null;
                    HttpMessage alertMessage = optionsmsg;
                    String extraInfo = null;
                    String description = null;
                    // if the threshold is Medium or above, then we need to confirm the vulnerability before alerting
                    boolean raiseAlert = false;
                    AlertThreshold threshold = getAlertThreshold();
                    if (threshold != AlertThreshold.LOW) {
                        // != Low threshold --> verify it
                        if (enabledmethod.equals(HTTP_METHOD_TRACE) || enabledmethod.equals(HTTP_METHOD_TRACK)) {
                            log.debug("Verifying a TRACE/TRACK");
                            MessageAndEvidence mae = testMethod(enabledmethod);
                            if (mae != null) {
                                evidence = mae.evidence;
                                alertMessage = mae.message;
                                raiseAlert = true;
                                description = Constant.messages
                                        .getString("ascanbeta.insecurehttpmethod.trace.exploitable.desc", enabledmethod);
                                extraInfo = Constant.messages
                                        .getString("ascanbeta.insecurehttpmethod.trace.exploitable.extrainfo", evidence);
                            }
                        } else if (enabledmethod.equals(HTTP_METHOD_CONNECT)) {
                            log.debug("Verifying a CONNECT");
                            // use a CONNECT method to establish a socket connection to a third party, via the server
                            // being tested
                            boolean connectWorks = testConnect(
                                    this.getBaseMsg(),
                                    thirdpartyHost,
                                    thirdpartyPort,
                                    thirdPartyContentPattern);
                            if (connectWorks) {
                                evidence = "";
                                alertMessage = optionsmsg; // there is no connectmessage, since the HttpSender does not
                                                           // support CONNECT
                                raiseAlert = true;
                                description = Constant.messages
                                        .getString("ascanbeta.insecurehttpmethod.connect.exploitable.desc", enabledmethod);
                                extraInfo = Constant.messages.getString(
                                        "ascanbeta.insecurehttpmethod.connect.exploitable.extrainfo",
                                        thirdpartyHost);
                            }
                        }
                    } else {
                        // == Low threshold --> no need to verify it
                        evidence = enabledmethod;
                        alertMessage = optionsmsg;
                        raiseAlert = true;
                        description = Constant.messages.getString("ascanbeta.insecurehttpmethod.desc", enabledmethod);
                        extraInfo = Constant.messages.getString("ascanbeta.insecurehttpmethod.extrainfo", allowedmethods);
                    }
                    if (raiseAlert) {
                        log.debug("Raising alert for Insecure HTTP Method");
                        bingo(
                                Alert.RISK_MEDIUM,
                                Alert.CONFIDENCE_MEDIUM,
                                Constant.messages.getString("ascanbeta.insecurehttpmethod.detailed.name", insecureMethod),
                                description,
                                null, // originalMessage.getRequestHeader().getURI().getURI(),
                                null, // parameter being attacked: none.
                                "", // attack
                                extraInfo,
                                Constant.messages.getString("ascanbeta.insecurehttpmethod.soln"),
                                evidence, // evidence,
                                          // highlighted in
                                          // the message
                                alertMessage);
                    }
                }
            }
        }
    }

    /**
     * Check for all HTTP methods defined in {@link #INSECURE_METHODS}. Raise an alert if one of them is supported.
     * 
     * @throws Exception
     */
    private void checkInsecureHttpMethods() throws Exception {
        for (String method : INSECURE_METHODS) {
            final MessageAndEvidence mae = testMethod(method);
            if (mae != null) {
                raiseAlert(mae);
            }
        }
    }

    private void raiseAlert(MessageAndEvidence mae) {
        log.debug("raising Alert for: " + mae);
        bingo(
                Alert.RISK_MEDIUM,
                Alert.CONFIDENCE_MEDIUM,
                Constant.messages.getString("ascanbeta.insecurehttpmethod.detailed.name", mae.getHttpMethod()),
                Constant.messages.getString("ascanbeta.insecurehttpmethod.trace.exploitable.desc", mae.getHttpMethod()),
                null, // originalMessage.getRequestHeader().getURI().getURI(),
                null, // parameter being attacked: none.
                "", // attack
                getExtraInfoMessageForHttpMethod(mae.getHttpMethod()),
                Constant.messages.getString("ascanbeta.insecurehttpmethod.soln"),
                mae.getEvidence(), // evidence, highlighted in the message
                mae.getMessage());
    }

    private final String getExtraInfoMessageForHttpMethod(String httpMethod) {

        if (httpMethod.equals(HTTP_METHOD_CONNECT)) {
            return Constant.messages.getString("ascanbeta.insecurehttpmethod.connect.exploitable.extrainfo", httpMethod);
        } else if (httpMethod.equals(HTTP_METHOD_TRACE)) {
            return Constant.messages.getString("ascanbeta.insecurehttpmethod.trace.exploitable.extrainfo", httpMethod);
        } else if (httpMethod.equals(HTTP_METHOD_DELETE)) {
            return Constant.messages.getString("ascanbeta.insecurehttpmethod.delete.exploitable.extrainfo", httpMethod);
        } else if (httpMethod.equals(HTTP_METHOD_PUT)) {
            return Constant.messages.getString("ascanbeta.insecurehttpmethod.put.exploitable.extrainfo", httpMethod);
        } else if (httpMethod.equals(HTTP_METHOD_TRACK)) {
            return Constant.messages.getString("ascanbeta.insecurehttpmethod.track.exploitable.extrainfo", httpMethod);
        }
        return null;
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

        private HttpMessage message = null;

        private String evidence = null;

        private String httpMethod = null;

        public MessageAndEvidence(HttpMessage message, String evidence, String httpMethod) {
            super();
            this.message = message;
            this.evidence = evidence;
            this.httpMethod = httpMethod;
        }

        @Override
        public String toString() {
            return "MessageAndEvidence [message=" + message + ", evidence=" + evidence + ", httpMethod=" + httpMethod + "]";
        }

        public final HttpMessage getMessage() {
            return message;
        }

        public final String getEvidence() {
            return evidence;
        }

        public final String getHttpMethod() {
            return httpMethod;
        }
    }

    private MessageAndEvidence testMethod(String method) throws Exception {

        final HttpRequestHeader traceRequestHeader = this.getBaseMsg().getRequestHeader();

        traceRequestHeader.setMethod(method);
        traceRequestHeader.setVersion(HttpRequestHeader.HTTP11);

        final HttpMessage tracemsg = getNewMsg();
        tracemsg.setRequestHeader(traceRequestHeader);
        sendAndReceive(tracemsg, true); // do not follow redirects. That might ruin our day.
        MessageAndEvidence ret = null;

        final int responseCode = tracemsg.getResponseHeader().getStatusCode();

        log.debug("Request Method: " + method);
        log.debug("Response Code: " + responseCode);

        if (responseCode == 200) {
            ret = new MessageAndEvidence(tracemsg, "200 for insecure HTTP METHOD", method);
        }

        return ret;
    }

    private boolean testConnect(
            HttpMessage baseMsg,
            String thirdpartyHost,
            int thirdpartyPort,
            Pattern thirdPartyContentPattern) throws Exception {

        final String connecthost = baseMsg.getRequestHeader().getURI().getHost();
        final int connectport = baseMsg.getRequestHeader().getURI().getPort();

        // this cannot currently be done using the existing HttpSender class, so do it natively using HttpClient,
        // in as simple as possible a manner.
        Socket socket = null;
        try {
            final ProxyClient client = new ProxyClient();
            client.getHostConfiguration().setProxy(connecthost, connectport);
            client.getHostConfiguration().setHost(thirdpartyHost, thirdpartyPort);
            final ConnectResponse connectResponse = client.connect();
            final StatusLine statusLine = connectResponse.getConnectMethod().getStatusLine();

            log.debug("The status line returned: " + statusLine);

            final int statusCode = statusLine.getStatusCode();
            socket = connectResponse.getSocket();
            if (socket != null && statusCode == HttpStatus.SC_OK) {

                // we have a socket and a 200 status.
                // Could still be a false positive though, if the server ignored the method,
                // and did not recognise the URL, so redirected to a login page, for instance
                // Remediation: Check the contents match the expected third party contents.

                log.debug("Raw Socket established, in theory to " + thirdpartyHost);

                final OutputStream os = socket.getOutputStream();
                final InputStream is = socket.getInputStream();

                final PrintWriter pw = new PrintWriter(os, false);
                pw.write("GET http://" + thirdpartyHost + ":" + thirdpartyPort + "/ HTTP/1.1\n");
                pw.write("Host: " + thirdpartyHost + "\n\n");
                pw.flush();

                // read the response via a 4k buffer
                final ByteArrayOutputStream bos = new ByteArrayOutputStream();
                final byte[] buffer = new byte[1024 * 4];
                int bytesRead = is.read(buffer);
                int totalBytesRead = 0;
                while (bytesRead > -1) {
                    totalBytesRead += bytesRead;
                    bos.write(buffer, 0, bytesRead);
                    bytesRead = is.read(buffer);
                }
                final String response = new String(bos.toByteArray());
                log.debug("Response is " + totalBytesRead + " bytes: \n" + response);
                final Matcher m = thirdPartyContentPattern.matcher(response);
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
                // socket == null OR statusCode != HttpStatus.SC_OK
                log.debug(
                        "Could not establish a socket connection to a third party using the CONNECT HTTP method: NULL socket returned, or non-200 response");
                log.debug("The status line returned: " + statusLine);
                return false;
            }
        } catch (Exception e) {
            log.error(
                    "Could not establish a socket connection to a third party using the CONNECT HTTP method: " + e.getMessage(),
                    e);
        }

        return false;
    }
}