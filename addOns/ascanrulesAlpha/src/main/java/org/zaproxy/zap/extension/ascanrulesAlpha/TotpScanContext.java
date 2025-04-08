/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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

import java.util.List;
import org.zaproxy.addon.authhelper.BrowserBasedAuthenticationMethodType.BrowserBasedAuthenticationMethod;
import org.zaproxy.addon.authhelper.internal.AuthenticationStep;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.session.SessionManagementMethod;
import org.zaproxy.zap.users.User;

// Bundles all the context information needed to perform a TOTP scan
public class TotpScanContext {
    public final Context context;
    public final BrowserBasedAuthenticationMethod browserAuthMethod;
    public final List<AuthenticationStep> authSteps;
    public final AuthenticationStep totpStep;
    public final UsernamePasswordAuthenticationCredentials credentials;
    public final SessionManagementMethod sessionManagementMethod;
    public final User user;

    public TotpScanContext(
            Context context,
            BrowserBasedAuthenticationMethod browserAuthMethod,
            List<AuthenticationStep> authSteps,
            AuthenticationStep totpStep,
            UsernamePasswordAuthenticationCredentials credentials,
            SessionManagementMethod sessionManagementMethod,
            User user) {
        this.context = context;
        this.browserAuthMethod = browserAuthMethod;
        this.authSteps = authSteps;
        this.totpStep = totpStep;
        this.credentials = credentials;
        this.sessionManagementMethod = sessionManagementMethod;
        this.user = user;
    }
}
