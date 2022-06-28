/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.client;

import java.time.Instant;
import java.util.Date;
import org.apache.commons.httpclient.Cookie;
import org.apache.commons.httpclient.HttpState;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.cookie.CookieStore;
import org.apache.hc.client5.http.impl.cookie.BasicClientCookie;

public final class LegacyUtils {

    private LegacyUtils() {}

    public static CookieStore httpStateToCookieStore(HttpState httpState) {
        BasicCookieStore cookieStore = new BasicCookieStore();
        if (httpState == null) {
            return cookieStore;
        }

        for (Cookie cookie : httpState.getCookies()) {
            BasicClientCookie c = new BasicClientCookie(cookie.getName(), cookie.getValue());
            c.setDomain(cookie.getDomain());
            c.setPath(cookie.getPath());
            c.setSecure(cookie.getSecure());
            Date expiryDate = cookie.getExpiryDate();
            if (expiryDate != null) {
                c.setExpiryDate(expiryDate.toInstant());
            }
            cookieStore.addCookie(c);
        }
        return cookieStore;
    }

    public static void updateHttpState(HttpState httpState, CookieStore cookieStore) {
        if (httpState == null) {
            return;
        }

        httpState.clearCookies();
        for (org.apache.hc.client5.http.cookie.Cookie cookie : cookieStore.getCookies()) {
            httpState.addCookie(
                    new Cookie(
                            cookie.getDomain(),
                            cookie.getName(),
                            cookie.getValue(),
                            cookie.getPath(),
                            getExpiryDate(cookie),
                            cookie.isSecure()));
        }
    }

    private static Date getExpiryDate(org.apache.hc.client5.http.cookie.Cookie cookie) {
        Instant expiry = cookie.getExpiryInstant();
        if (expiry != null) {
            return new Date(expiry.toEpochMilli());
        }
        return null;
    }
}
