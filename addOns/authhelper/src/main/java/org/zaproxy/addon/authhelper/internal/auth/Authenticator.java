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
package org.zaproxy.addon.authhelper.internal.auth;

import java.util.List;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.authhelper.AuthenticationDiagnostics;
import org.zaproxy.addon.authhelper.internal.AuthenticationStep;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;
import org.zaproxy.zap.model.Context;

public interface Authenticator {

    public static final Result NO_AUTH = new Result(false, false, false, false);

    public static record Result(
            boolean isAttempted, boolean isSuccessful, boolean hasUserField, boolean hasPwdField) {}

    boolean isOwnSite(HttpMessage msg);

    Result authenticate(
            AuthenticationDiagnostics diags,
            WebDriver wd,
            Context context,
            String loginPageUrl,
            UsernamePasswordAuthenticationCredentials credentials,
            int stepDelayInSecs,
            int waitInSecs,
            List<AuthenticationStep> steps);
}
