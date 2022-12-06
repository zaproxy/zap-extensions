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
package org.zaproxy.addon.network.internal.codec;

import static io.netty.handler.codec.http.HttpHeaderNames.COOKIE;
import static io.netty.handler.codec.http2.Http2Error.PROTOCOL_ERROR;
import static io.netty.handler.codec.http2.Http2Exception.streamError;

import io.netty.handler.codec.http2.DefaultHttp2Headers;
import io.netty.handler.codec.http2.Http2Exception;
import io.netty.handler.codec.http2.Http2Headers;
import io.netty.util.AsciiString;
import io.netty.util.internal.InternalThreadLocalMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;

/** Helper class to map between {@link HttpMessage} and {@link Http2Headers}. */
public class Http2MessageHelper {

    private static final String HOST = HttpRequestHeader.HOST.toLowerCase(Locale.ROOT);

    private Http2MessageHelper() {}

    public static void setHttpRequest(int streamId, Http2Headers headers, HttpMessage msg)
            throws Http2Exception {
        try {
            String content = createRequestContent(streamId, headers);
            msg.getRequestHeader().setMessage(content, hasHttpsScheme(headers));

            copyHeaders(streamId, headers, msg, true);
        } catch (Http2Exception e) {
            throw e;
        } catch (Throwable t) {
            throw streamError(streamId, PROTOCOL_ERROR, t, t.getMessage());
        }
    }

    private static boolean isEmpty(CharSequence string) {
        return string == null || string.length() == 0;
    }

    private static boolean hasHttpsScheme(Http2Headers headers) {
        CharSequence scheme = headers.scheme();
        if (isEmpty(scheme)) {
            return false;
        }
        return HttpHeader.HTTPS.equalsIgnoreCase(scheme.toString());
    }

    private static String createRequestContent(int streamId, Http2Headers headers)
            throws Http2Exception {
        String method = Optional.ofNullable(headers.method()).map(Object::toString).orElse("");
        if (isEmpty(method)) {
            throw streamError(streamId, PROTOCOL_ERROR, "HTTP/2 headers does not have a method.");
        }

        CharSequence authority = headers.authority();
        if (isEmpty(authority)) {
            throw streamError(
                    streamId, PROTOCOL_ERROR, "HTTP/2 headers does not have an authority.");
        }

        if (HttpRequestHeader.CONNECT.equalsIgnoreCase(method)) {
            return method + " " + headers.authority() + " HTTP/2";
        }

        CharSequence scheme = headers.scheme();
        if (isEmpty(scheme)) {
            throw streamError(streamId, PROTOCOL_ERROR, "HTTP/2 headers does not have a scheme.");
        }

        CharSequence path = headers.path();
        if (HttpRequestHeader.OPTIONS.equalsIgnoreCase(method) && "*".equals(path)) {
            return method + " " + path + " HTTP/2";
        }

        if (isEmpty(path)) {
            path = "/";
        }

        return method + " " + scheme + "://" + headers.authority() + path + " HTTP/2";
    }

    public static void setHttpResponse(int streamId, Http2Headers headers, HttpMessage msg)
            throws Http2Exception {
        CharSequence status = headers.status();
        if (isEmpty(status)) {
            throw streamError(streamId, PROTOCOL_ERROR, "HTTP/2 headers does not have a status.");
        }

        try {
            msg.getResponseHeader().setMessage("HTTP/2 " + status);

            copyHeaders(streamId, headers, msg, false);
        } catch (Http2Exception e) {
            throw e;
        } catch (Throwable t) {
            throw streamError(streamId, PROTOCOL_ERROR, t, t.getMessage());
        }
    }

    public static void copyHeaders(
            int streamId, Http2Headers from, HttpMessage to, boolean toRequest)
            throws Http2Exception {
        HttpHeader toHeader = toRequest ? to.getRequestHeader() : to.getResponseHeader();
        try {
            StringBuilder cookies = null;

            for (Entry<CharSequence, CharSequence> entry : from) {
                CharSequence name = entry.getKey();
                CharSequence value = entry.getValue();

                if (!Http2Headers.PseudoHeaderName.isPseudoHeader(name)) {
                    if (COOKIE.contentEqualsIgnoreCase(name)) {
                        if (cookies == null) {
                            cookies = InternalThreadLocalMap.get().stringBuilder();
                        } else if (cookies.length() > 0) {
                            cookies.append("; ");
                        }
                        cookies.append(value);
                    } else {
                        toHeader.addHeader(name.toString(), value.toString());
                    }
                }
            }

            if (cookies != null) {
                toHeader.addHeader(COOKIE.toString(), cookies.toString());
            }
        } catch (Throwable t) {
            throw streamError(streamId, PROTOCOL_ERROR, t, t.getMessage());
        }

        toHeader.setHeader(HttpHeader.TRANSFER_ENCODING, null);
    }

    public static void addTrailerHeaders(
            int streamId, Http2Headers from, HttpMessage to, boolean toRequest)
            throws Http2Exception {
        List<HttpHeaderField> trailers = getTrailerHeaders(to, toRequest);

        for (Entry<CharSequence, CharSequence> entry : from) {
            trailers.add(
                    new HttpHeaderField(entry.getKey().toString(), entry.getValue().toString()));
        }
    }

    @SuppressWarnings("unchecked")
    private static List<HttpHeaderField> getTrailerHeaders(HttpMessage to, boolean request) {
        String key = request ? "zap.h2.trailers.req" : "zap.h2.trailers.resp";
        Map<String, Object> properties = (Map<String, Object>) to.getUserObject();
        if (properties == null) {
            properties = new HashMap<>();
        }
        return (List<HttpHeaderField>) properties.computeIfAbsent(key, k -> new ArrayList<>());
    }

    public static Http2Headers createHttp2Headers(String scheme, HttpHeader from) {
        List<HttpHeaderField> headers = from.getHeaders();
        Http2Headers to = new DefaultHttp2Headers(false, headers.size());
        if (from instanceof HttpRequestHeader) {
            HttpRequestHeader request = (HttpRequestHeader) from;
            to.scheme(scheme);
            to.method(request.getMethod());

            URI uri = request.getURI();
            String pathQuery = uri.getEscapedPathQuery();
            if (isEmpty(pathQuery)) {
                to.path("/");
            } else {
                to.path(pathQuery);
            }

            String host = from.getHeader(HOST);
            to.authority(isEmpty(host) ? uri.getEscapedAuthority() : host);
        } else {
            HttpResponseHeader response = (HttpResponseHeader) from;
            to.status(String.valueOf(response.getStatusCode()));
        }

        copyHeaders(headers, to);

        return to;
    }

    public static Http2Headers createTrailerHttp2Headers(HttpMessage from, boolean request) {
        List<HttpHeaderField> trailers = getTrailerHeaders(from, request);
        Http2Headers to = new DefaultHttp2Headers(false, trailers.size());
        copyHeaders(trailers, to);
        return to;
    }

    private static void copyHeaders(List<HttpHeaderField> from, Http2Headers to) {
        for (HttpHeaderField entry : from) {
            AsciiString name = AsciiString.of(entry.getName()).toLowerCase();
            if (name.contentEquals(COOKIE)) {
                copyCookies(entry, to);
            } else {
                to.add(name, entry.getValue());
            }
        }
    }

    private static void copyCookies(HttpHeaderField entry, Http2Headers to) {
        for (String cookie : entry.getValue().split("; *", -1)) {
            to.add(COOKIE, cookie);
        }
    }
}
