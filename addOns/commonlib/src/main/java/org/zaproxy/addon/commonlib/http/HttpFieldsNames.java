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
package org.zaproxy.addon.commonlib.http;

/**
 * The names of standard and common HTTP Fields.
 *
 * @since 1.12.0
 */
public final class HttpFieldsNames {

    public static final String ACCEPT = "accept";
    public static final String ACCEPT_ENCODING = "accept-encoding";
    public static final String ACCESS_CONTROL_ALLOW_CREDENTIALS =
            "access-control-allow-credentials";
    public static final String ACCESS_CONTROL_ALLOW_HEADERS = "access-control-allow-headers";
    public static final String ACCESS_CONTROL_ALLOW_METHODS = "access-control-allow-methods";
    public static final String ACCESS_CONTROL_ALLOW_ORIGIN = "access-control-allow-origin";
    public static final String ACCESS_CONTROL_EXPOSE_HEADERS = "access-control-expose-headers";
    public static final String ALLOW = "allow";
    public static final String AUTHORIZATION = "authorization";
    public static final String CACHE_CONTROL = "cache-control";
    public static final String CONNECTION = "connection";
    public static final String CONTENT_ENCODING = "content-encoding";
    public static final String CONTENT_LENGTH = "content-length";
    public static final String CONTENT_LOCATION = "content-location";
    public static final String CONTENT_SECURITY_POLICY = "content-security-policy";
    public static final String CONTENT_SECURITY_POLICY_REPORT_ONLY =
            "content-security-policy-report-only";
    public static final String CONTENT_TYPE = "content-type";
    public static final String COOKIE = "cookie";
    public static final String EXPIRE = "expire";
    public static final String HOST = "host";
    public static final String IF_MODIFIED_SINCE = "if-modified-since";
    public static final String IF_NONE_MATCH = "if-none-match";
    public static final String LINK = "link";
    public static final String LOCATION = "location";
    public static final String MAX_FORWARDS = "max-forwards";
    public static final String ORIGIN = "origin";
    public static final String PRAGMA = "pragma";
    public static final String PROXY = "proxy";
    public static final String PROXY_AUTHENTICATE = "proxy-authenticate";
    public static final String PROXY_AUTHORIZATION = "proxy-authorization";
    public static final String PROXY_CONNECTION = "proxy-connection";
    public static final String PUBLIC = "public";
    public static final String REFERER = "referer";
    public static final String REFRESH = "refresh";
    public static final String SERVER = "server";
    public static final String SET_COOKIE = "set-cookie";
    public static final String SET_COOKIE2 = "set-cookie2";
    public static final String TRANSFER_ENCODING = "transfer-encoding";
    public static final String USER_AGENT = "user-agent";
    public static final String WWW_AUTHENTICATE = "www-authenticate";
    public static final String X_CONTENT_SECURITY_POLICY = "x-content-security-policy";
    public static final String X_CONTENT_TYPE_OPTIONS = "x-content-type-options";
    public static final String X_CSRF_TOKEN = "x-csrf-token";
    public static final String X_CSRFTOKEN = "x-csrftoken";
    public static final String X_FORWARDED_FOR = "x-forwarded-for";
    public static final String X_FRAME_OPTIONS = "x-frame-options";
    public static final String X_ORIGINAL_URL = "x-original-url";
    public static final String X_POWERED_BY = "x-powered-by";
    public static final String X_REWRITE_URL = "x-rewrite-url";
    public static final String X_WEBKIT_CSP = "x-webkit-csp";
    public static final String X_XSRF_TOKEN = "x-xsrf-token";
    public static final String X_XSS_PROTECTION = "x-xss-protection";

    private HttpFieldsNames() {}
}
