/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.client.spider;

import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.commonlib.http.HttpDateUtils;
import org.zaproxy.zap.utils.Stats;

/**
 * A cache of static resources (e.g. stylesheets, scripts, images, fonts) fetched during a crawl,
 * used to answer repeated requests for the same resource without sending them to the server again.
 *
 * <p>Only successful (200) responses to GET requests without an {@code Authorization} header are
 * cached, and only when the response has a clearly static content type and does not opt out of
 * caching ({@code Cache-Control: no-store}, {@code no-cache}, or {@code private}, or a {@code Vary}
 * header other than {@code Accept-Encoding}). Repeated requests are answered with a 304 when they
 * include validators matching the cached response, otherwise with the cached response itself.
 *
 * <p>The cache is expected to live for the duration of a single crawl.
 */
class StaticResourceCache {

    private static final Logger LOGGER = LogManager.getLogger(StaticResourceCache.class);

    private static final int MAX_ENTRIES = 500;

    private static final int MAX_BODY_SIZE = 1024 * 1024;

    private static final List<String> STATIC_CONTENT_TYPES =
            List.of(
                    "text/css",
                    "text/javascript",
                    "application/javascript",
                    "application/x-javascript",
                    "application/ecmascript",
                    "image/",
                    "font/",
                    "application/font",
                    "application/vnd.ms-fontobject");

    private static final String CACHE_CONTROL_HEADER = "Cache-Control";
    private static final String DATE_HEADER = "Date";
    private static final String ETAG_HEADER = "ETag";
    private static final String EXPIRES_HEADER = "Expires";
    private static final String LAST_MODIFIED_HEADER = "Last-Modified";
    private static final String VARY_HEADER = "Vary";
    private static final String ACCEPT_ENCODING = "Accept-Encoding";

    /** Headers of the stored response that a 304 should also carry (RFC 9110, Section 15.4.5). */
    private static final List<String> HEADERS_304 =
            List.of(
                    CACHE_CONTROL_HEADER,
                    ETAG_HEADER,
                    EXPIRES_HEADER,
                    LAST_MODIFIED_HEADER,
                    VARY_HEADER);

    private final Map<String, CachedResponse> cache =
            new LinkedHashMap<>(16, 0.75f, true) {

                private static final long serialVersionUID = 1L;

                @Override
                protected boolean removeEldestEntry(Map.Entry<String, CachedResponse> eldest) {
                    return size() > MAX_ENTRIES;
                }
            };

    /**
     * Handles the given request, serving the cached response if available.
     *
     * @param msg the message with the request, to which the cached response is set.
     * @return {@code true} if the response was served from the cache, {@code false} otherwise.
     */
    boolean handleRequest(HttpMessage msg) {
        HttpRequestHeader requestHeader = msg.getRequestHeader();
        if (!isCacheableRequest(requestHeader)) {
            return false;
        }

        CachedResponse cached;
        synchronized (cache) {
            cached = cache.get(createKey(requestHeader));
        }
        if (cached == null) {
            return false;
        }

        try {
            if (matchesValidators(requestHeader, cached)) {
                msg.setResponseHeader(create304Response(cached));
                msg.setResponseBody(new byte[0]);
            } else {
                msg.setResponseHeader(cached.responseHeader);
                msg.setResponseBody(Arrays.copyOf(cached.body, cached.body.length));
                msg.getResponseHeader().setContentLength(cached.body.length);
            }
        } catch (HttpMalformedHeaderException e) {
            LOGGER.warn("Failed to set the cached response:", e);
            return false;
        }

        msg.setTimeSentMillis(System.currentTimeMillis());
        msg.setTimeElapsedMillis(0);
        Stats.incCounter("stats.client.spider.cache.hits");
        return true;
    }

    /**
     * Handles the given response, caching it if cacheable.
     *
     * @param msg the message with the response.
     */
    void handleResponse(HttpMessage msg) {
        HttpRequestHeader requestHeader = msg.getRequestHeader();
        if (!isCacheableRequest(requestHeader)) {
            return;
        }

        HttpResponseHeader responseHeader = msg.getResponseHeader();
        if (responseHeader.getStatusCode() != HttpStatusCode.OK
                || msg.getResponseBody().length() > MAX_BODY_SIZE
                || !isStaticContentType(responseHeader.getHeader(HttpHeader.CONTENT_TYPE))
                || !isCacheableResponse(responseHeader)) {
            return;
        }

        byte[] body = msg.getResponseBody().getBytes();
        CachedResponse cached =
                new CachedResponse(
                        responseHeader.toString(),
                        Arrays.copyOf(body, body.length),
                        responseHeader.getHeader(ETAG_HEADER),
                        responseHeader.getHeader(LAST_MODIFIED_HEADER));
        synchronized (cache) {
            cache.put(createKey(requestHeader), cached);
        }
    }

    private static String createKey(HttpRequestHeader requestHeader) {
        return requestHeader.getURI().getEscapedURI();
    }

    private static boolean isCacheableRequest(HttpRequestHeader requestHeader) {
        return HttpRequestHeader.GET.equals(requestHeader.getMethod())
                && requestHeader.getHeader(HttpHeader.AUTHORIZATION) == null;
    }

    private static boolean isStaticContentType(String contentType) {
        if (contentType == null) {
            return false;
        }
        String normalised = contentType.trim().toLowerCase(Locale.ROOT);
        return STATIC_CONTENT_TYPES.stream().anyMatch(normalised::startsWith);
    }

    private static boolean isCacheableResponse(HttpResponseHeader responseHeader) {
        String cacheControl = responseHeader.getHeader(HttpHeader.CACHE_CONTROL);
        if (cacheControl != null) {
            String normalised = cacheControl.toLowerCase(Locale.ROOT);
            if (normalised.contains("no-store")
                    || normalised.contains("no-cache")
                    || normalised.contains("private")) {
                return false;
            }
        }

        String vary = responseHeader.getHeader(VARY_HEADER);
        return vary == null || ACCEPT_ENCODING.equalsIgnoreCase(vary.trim());
    }

    private static boolean matchesValidators(
            HttpRequestHeader requestHeader, CachedResponse cached) {
        String ifNoneMatch = requestHeader.getHeader(HttpHeader.IF_NONE_MATCH);
        if (ifNoneMatch != null) {
            if (cached.etag == null) {
                return false;
            }
            for (String value : ifNoneMatch.split(",")) {
                if (cached.etag.equals(value.trim())) {
                    return true;
                }
            }
            return false;
        }

        String ifModifiedSince = requestHeader.getHeader(HttpHeader.IF_MODIFIED_SINCE);
        return ifModifiedSince != null && ifModifiedSince.equals(cached.lastModified);
    }

    private static HttpResponseHeader create304Response(CachedResponse cached)
            throws HttpMalformedHeaderException {
        HttpResponseHeader stored = new HttpResponseHeader(cached.responseHeader);
        StringBuilder strBuilder = new StringBuilder(250);
        strBuilder.append("HTTP/1.1 304 Not Modified").append(HttpHeader.CRLF);
        strBuilder
                .append(DATE_HEADER)
                .append(": ")
                .append(HttpDateUtils.format(Instant.now()))
                .append(HttpHeader.CRLF);
        for (String name : HEADERS_304) {
            String value = stored.getHeader(name);
            if (value != null) {
                strBuilder.append(name).append(": ").append(value).append(HttpHeader.CRLF);
            }
        }
        return new HttpResponseHeader(strBuilder.toString());
    }

    private static class CachedResponse {

        private final String responseHeader;
        private final byte[] body;
        private final String etag;
        private final String lastModified;

        CachedResponse(String responseHeader, byte[] body, String etag, String lastModified) {
            this.responseHeader = responseHeader;
            this.body = body;
            this.etag = etag;
            this.lastModified = lastModified;
        }
    }
}
