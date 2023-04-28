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

import java.util.Comparator;
import java.util.List;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.zap.authentication.AuthenticationCredentials;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.extension.users.ExtensionUserManagement;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.users.User;

public class VerificationRequestDetails {

    private final HttpMessage msg;
    private final String token;
    private boolean containsUserDetails;
    private boolean structuredResponse;
    private String evidence = "";
    private int contextId;

    public VerificationRequestDetails() {
        this.msg = null;
        this.token = null;
    }

    public VerificationRequestDetails(HttpMessage msg, String token, Context context) {
        this.msg = msg;
        this.token = token;
        this.contextId = context.getId();
        structuredResponse = msg.getResponseHeader().isJson() || msg.getResponseHeader().isXml();

        ExtensionUserManagement extUsers =
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionUserManagement.class);
        if (extUsers != null) {
            String responseBody = msg.getResponseBody().toString();

            List<User> users = extUsers.getContextUserAuthManager(contextId).getUsers();
            for (User user : users) {
                if (responseBody.contains(user.getName())) {
                    containsUserDetails = true;
                    this.setEvidence(user.getName());
                    break;
                }
                AuthenticationCredentials creds = user.getAuthenticationCredentials();
                if (creds instanceof UsernamePasswordAuthenticationCredentials) {
                    UsernamePasswordAuthenticationCredentials upCreds =
                            (UsernamePasswordAuthenticationCredentials) creds;
                    if (responseBody.contains(upCreds.getUsername())) {
                        containsUserDetails = true;
                        this.setEvidence(upCreds.getUsername());
                        break;
                    }
                }
            }
        }
    }

    public boolean isConsistent(VerificationRequestDetails vrd) {
        return this.getResponseCode() == vrd.getResponseCode()
                && isStructuredResponse() == vrd.isStructuredResponse()
                && isContainsUserDetails() == vrd.isContainsUserDetails()
                && (getResponseSize() / 10) == (vrd.getResponseSize() / 10);
    }

    public boolean isIdentifiablyDifferent(VerificationRequestDetails vrd) {
        return getResponseCode() != vrd.getResponseCode()
                || isContainsUserDetails() != vrd.isContainsUserDetails();
    }

    public HttpMessage getMsg() {
        return msg;
    }

    public String getToken() {
        return token;
    }

    public int getResponseCode() {
        if (msg != null) {
            return msg.getResponseHeader().getStatusCode();
        }
        return -1;
    }

    public int getResponseSize() {
        if (msg != null) {
            return msg.getResponseBody().length();
        }
        return -1;
    }

    public int getScore() {
        if (msg == null) {
            return -1;
        }
        int score = 0;
        if (this.getResponseCode() == HttpStatusCode.OK) {
            score += 1;
        }
        if ("GET".equals(this.msg.getRequestHeader().getMethod())) {
            score += 2;
        }
        if (this.isStructuredResponse()) {
            score += 4;
        }
        if (this.containsUserDetails) {
            score += 8;
        }

        return score;
    }

    public int getConfidence() {
        int score = this.getScore();
        if (score > 8) {
            return Alert.CONFIDENCE_HIGH;
        }
        if (score > 4) {
            return Alert.CONFIDENCE_MEDIUM;
        }
        if (score >= 0) {
            return Alert.CONFIDENCE_LOW;
        }
        return -1;
    }

    public boolean isContainsUserDetails() {
        return containsUserDetails;
    }

    public boolean isStructuredResponse() {
        return structuredResponse;
    }

    public String getEvidence() {
        return evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }

    public int getContextId() {
        return contextId;
    }

    public static VerificationComparator getComparator() {
        return new VerificationComparator();
    }

    public static class VerificationComparator implements Comparator<VerificationRequestDetails> {

        @Override
        public int compare(VerificationRequestDetails o1, VerificationRequestDetails o2) {
            return Integer.compare(o1.getScore(), o2.getScore());
        }
    }
}
