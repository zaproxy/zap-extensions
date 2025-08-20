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
package org.zaproxy.addon.commonlib;

import java.util.HashSet;
import java.util.Set;

/**
 * Constants related to authentication.
 *
 * @since 1.33.0
 */
public final class AuthConstants {

    private static final Set<String> LOGIN_INDICATORS =
            Set.of("login", "signin", "sign-in", "inloggen", "accueil");

    private static final Set<String> REGISTRATION_INDICATORS =
            Set.of("register", "signup", "sign-up");

    private static final Set<String> LOGOUT_INDICATORS =
            Set.of(
                    "logout",
                    "logoff",
                    "signout",
                    "signoff",
                    "log-out",
                    "sign-out",
                    "log-off",
                    "sign-off");

    private static final Set<String> AUTHENTICATION_RELATED_INDICATORS;

    static {
        AUTHENTICATION_RELATED_INDICATORS = new HashSet<>();
        AUTHENTICATION_RELATED_INDICATORS.addAll(LOGOUT_INDICATORS);
        AUTHENTICATION_RELATED_INDICATORS.addAll(LOGIN_INDICATORS);
        AUTHENTICATION_RELATED_INDICATORS.addAll(REGISTRATION_INDICATORS);
    }

    private AuthConstants() {}

    /**
     * @return A set of Strings which represent indications of a login page or parameter value.
     */
    public static Set<String> getLoginIndicators() {
        return LOGIN_INDICATORS;
    }

    /**
     * @return A set of Strings which represent indications of a logout URL or parameter value.
     * @since 1.35.0
     */
    public static Set<String> getLogoutIndicators() {
        return LOGOUT_INDICATORS;
    }

    /**
     * @return A set of Strings which represent indications of a registration page or parameter
     *     value.
     */
    public static Set<String> getRegistrationIndicators() {
        return REGISTRATION_INDICATORS;
    }

    /**
     * @return A set of Strings which represent various pages/functionality related to
     *     authentication. This includes: login, registration, and logout type values.
     */
    public static Set<String> getAuthRelatedIndicators() {
        return AUTHENTICATION_RELATED_INDICATORS;
    }
}
