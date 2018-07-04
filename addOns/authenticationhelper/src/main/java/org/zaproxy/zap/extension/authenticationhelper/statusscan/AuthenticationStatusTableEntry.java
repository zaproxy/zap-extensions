/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.authenticationhelper.statusscan;

import org.parosproxy.paros.model.HistoryReference;
import org.zaproxy.zap.view.table.DefaultHistoryReferencesTableEntry;

public class AuthenticationStatusTableEntry extends DefaultHistoryReferencesTableEntry {

    public static enum AuthenticationStatus {
        SUCCESSFULL,
        FAILED,
        CONFLICTING,
        UNKNOWN;
    }

    private final AuthenticationStatusTableEntry.AuthenticationStatus authenticationStatus;
    private final AuthenticationStatusScanner.IndicatorStatus loggedInIndicatorStatus;
    private final AuthenticationStatusScanner.IndicatorStatus loggedOutIndicatorStatus;

    public AuthenticationStatusTableEntry(
            HistoryReference historyReference,
            AuthenticationStatusTableEntry.AuthenticationStatus authenticationStatus,
            AuthenticationStatusScanner.IndicatorStatus loggedInIndicatorStatus,
            AuthenticationStatusScanner.IndicatorStatus loggedOutIndicatorStatus) {
        super(historyReference, AuthenticationStatusTableModel.COLUMNS);
        this.authenticationStatus = authenticationStatus;
        this.loggedInIndicatorStatus = loggedInIndicatorStatus;
        this.loggedOutIndicatorStatus = loggedOutIndicatorStatus;
    }

    public AuthenticationStatusTableEntry.AuthenticationStatus getAuthenticationStatus() {
        return authenticationStatus;
    }

    public AuthenticationStatusScanner.IndicatorStatus getLoggedInIndicatorStatus() {
        return loggedInIndicatorStatus;
    }

    public AuthenticationStatusScanner.IndicatorStatus getLoggedOutIndicatorStatus() {
        return loggedOutIndicatorStatus;
    }

    @Override
    public String toString() {
        return "AuthenticationStatusTableEntry [authenticationStatus="
                + authenticationStatus
                + ", loggedInIndicatorStatus="
                + loggedInIndicatorStatus
                + ", loggedOutIndicatorStatus="
                + loggedOutIndicatorStatus
                + "]";
    }
}
