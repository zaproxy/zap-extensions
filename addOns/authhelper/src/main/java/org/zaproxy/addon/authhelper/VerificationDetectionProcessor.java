/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.authhelper;

import java.io.IOException;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.authhelper.VerificationRequestDetails.VerificationComparator;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.AuthenticationMethod.AuthCheckingStrategy;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.utils.Stats;

public class VerificationDetectionProcessor implements Runnable {

    private static final VerificationComparator COMPARATOR =
            VerificationRequestDetails.getComparator();
    private static final Logger LOGGER = LogManager.getLogger(VerificationDetectionProcessor.class);

    private final Context context;
    private final VerificationDetectionScanRule rule;
    private final VerificationRequestDetails details;
    private final HttpSender httpSender =
            new HttpSender(HttpSender.AUTHENTICATION_HELPER_INITIATOR);

    public VerificationDetectionProcessor(
            Context context,
            VerificationRequestDetails details,
            VerificationDetectionScanRule rule) {
        this.context = context;
        this.details = details;
        this.rule = rule;
    }

    private static String getResponseCodeDetails(HttpMessage msg) {
        String line1 = msg.getResponseHeader().getPrimeHeader();
        return line1.substring(line1.indexOf(" " + msg.getResponseHeader().getStatusCode()));
    }

    @Override
    public void run() {

        VerificationRequestDetails currentDetails =
                AuthUtils.getVerificationDetailsForContext(context.getId());

        if (currentDetails == null || COMPARATOR.compare(details, currentDetails) <= 0) {
            return;
        }

        try {
            VerificationRequestDetails firstAuthVrd = details;
            VerificationRequestDetails firstNonAuthVrd = repeatRequest(firstAuthVrd, false);

            boolean goodVerifReq = true;
            for (int i = 0; i < 3; i++) {
                VerificationRequestDetails nonAuth = repeatRequest(firstAuthVrd, false);
                if (firstAuthVrd.isConsistent(nonAuth)) {
                    // The auth and non auth requests are consistent, so no good for our
                    // purposes
                    goodVerifReq = false;
                    break;
                }
                if (firstNonAuthVrd == null) {
                    firstNonAuthVrd = nonAuth;
                } else if (!firstNonAuthVrd.isConsistent(nonAuth)) {
                    // The non auth request is not consistent with the first, so no good for our
                    // purposes
                    goodVerifReq = false;
                    break;
                }
                VerificationRequestDetails auth = repeatRequest(firstAuthVrd, true);
                if (!firstAuthVrd.isConsistent(auth)) {
                    // The auth request is not consistent with the first, so no good for our
                    // purposes
                    goodVerifReq = false;
                    break;
                }
            }
            if (goodVerifReq) {
                String loggedInIndicator = details.getEvidence();
                String loggedOutIndicator = "";

                if (details.getResponseCode() != firstNonAuthVrd.getResponseCode()) {
                    // The response code details are better to use than specific user names
                    String okCode = getResponseCodeDetails(details.getMsg());
                    loggedInIndicator = okCode;
                    loggedOutIndicator =
                            Pattern.quote(getResponseCodeDetails(firstNonAuthVrd.getMsg()));
                    if (!details.isContainsUserDetails()) {
                        details.setEvidence(okCode);
                    }
                }

                if (!loggedInIndicator.isEmpty()) {
                    loggedInIndicator = Pattern.quote(loggedInIndicator);

                    rule.getAlert(details).raise();

                    updateContext(loggedInIndicator, loggedOutIndicator);
                }
            }
        } catch (IOException e) {
            LOGGER.debug(e.getMessage(), e);
        }
    }

    private synchronized void updateContext(String loggedInIndicator, String loggedOutIndicator) {
        if (COMPARATOR.compare(details, AuthUtils.getVerificationDetailsForContext(context.getId()))
                <= 0) {
            // Double check another thread hasnt set a better one in the meantime
            return;
        }

        // Update the context
        AuthenticationMethod authMethod = context.getAuthenticationMethod();
        authMethod.setAuthCheckingStrategy(AuthCheckingStrategy.POLL_URL);
        authMethod.setPollUrl(details.getMsg().getRequestHeader().getURI().toString());
        authMethod.setLoggedInIndicatorPattern(loggedInIndicator);
        authMethod.setLoggedOutIndicatorPattern(loggedOutIndicator);
        authMethod.setPollData(details.getMsg().getRequestBody().toString());

        StringBuilder sb = new StringBuilder();
        appendHeader(sb, details.getMsg().getRequestHeader(), HttpHeader.CONTENT_TYPE);
        appendHeader(sb, details.getMsg().getRequestHeader(), HttpHeader.REFERER);
        if (!sb.isEmpty()) {
            authMethod.setPollHeaders(sb.toString());
        }
        AuthUtils.setVerificationDetailsForContext(context.getId(), details);
        Stats.incCounter("stats.auth.configure.verification");
    }

    private void appendHeader(StringBuilder sb, HttpRequestHeader reqHeader, String headerName) {
        String headerValue = reqHeader.getHeader(headerName);
        if (headerValue != null) {
            sb.append(headerName);
            sb.append(": ");
            sb.append(headerValue);
            sb.append("\n");
        }
    }

    private VerificationRequestDetails repeatRequest(VerificationRequestDetails vrd, boolean auth)
            throws IOException {
        HttpMessage msg;
        if (auth) {
            msg = vrd.getMsg().cloneRequest();
        } else {
            HttpRequestHeader origReqHeader = vrd.getMsg().getRequestHeader();
            msg =
                    new HttpMessage(
                            new HttpRequestHeader(
                                    origReqHeader.getMethod(),
                                    origReqHeader.getURI(),
                                    origReqHeader.getVersion()));
            msg.getRequestHeader()
                    .setHeader(
                            HttpRequestHeader.CONTENT_TYPE,
                            origReqHeader.getHeader(HttpRequestHeader.CONTENT_TYPE));
            msg.getRequestHeader()
                    .setHeader(
                            HttpRequestHeader.REFERER,
                            origReqHeader.getHeader(HttpRequestHeader.REFERER));

            msg.getRequestBody().setBody(vrd.getMsg().getRequestBody().getBytes());
            msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
        }
        httpSender.sendAndReceive(msg);
        return new VerificationRequestDetails(msg, vrd.getToken(), context);
    }
}
