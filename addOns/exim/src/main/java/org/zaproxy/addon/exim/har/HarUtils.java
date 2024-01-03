/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.exim.har;

import de.sstoehr.harreader.model.HarCache;
import de.sstoehr.harreader.model.HarContent;
import de.sstoehr.harreader.model.HarCookie;
import de.sstoehr.harreader.model.HarCreatorBrowser;
import de.sstoehr.harreader.model.HarEntry;
import de.sstoehr.harreader.model.HarHeader;
import de.sstoehr.harreader.model.HarLog;
import de.sstoehr.harreader.model.HarPostData;
import de.sstoehr.harreader.model.HarPostDataParam;
import de.sstoehr.harreader.model.HarQueryParam;
import de.sstoehr.harreader.model.HarRequest;
import de.sstoehr.harreader.model.HarResponse;
import de.sstoehr.harreader.model.HarTiming;
import de.sstoehr.harreader.model.HttpMethod;
import de.sstoehr.harreader.model.HttpStatus;
import java.net.HttpCookie;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HtmlParameter;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.network.HttpRequestBody;

/**
 * Utility class to parse/create HTTP Archives (HAR) and do conversions between HAR Java classes and
 * {@code HttpMessage}s (request and response).
 *
 * @see <a href="http://www.softwareishard.com/blog/har-12-spec/">HTTP Archive 1.2</a>
 * @see HttpMessage
 */
public final class HarUtils {

    private static final Logger LOGGER = LogManager.getLogger(HarUtils.class);

    private HarUtils() {}

    public static HttpMessage createHttpMessage(HarRequest harRequest)
            throws HttpMalformedHeaderException {
        StringBuilder strBuilderReqHeader = new StringBuilder();

        strBuilderReqHeader
                .append(harRequest.getMethod())
                .append(' ')
                .append(harRequest.getUrl())
                .append(' ')
                .append(harRequest.getHttpVersion())
                .append("\r\n");

        for (HarHeader harHeader : harRequest.getHeaders()) {
            strBuilderReqHeader
                    .append(harHeader.getName())
                    .append(": ")
                    .append(harHeader.getValue())
                    .append("\r\n");
        }
        strBuilderReqHeader.append("\r\n");

        StringBuilder strBuilderReqBody = new StringBuilder();
        final HarPostData harPostData = harRequest.getPostData();
        if (harPostData != null) {
            final String text = harPostData.getText();
            if (text != null && !text.isEmpty()) {
                strBuilderReqBody.append(harRequest.getPostData().getText());
            } else if (harPostData.getParams() != null && !harPostData.getParams().isEmpty()) {
                for (HarPostDataParam param : harRequest.getPostData().getParams()) {
                    if (strBuilderReqBody.length() > 0) {
                        strBuilderReqBody.append('&');
                    }
                    strBuilderReqBody.append(param.getName()).append('=').append(param.getValue());
                }
            }
        }

        HttpRequestHeader header = null;
        try {
            header = new HttpRequestHeader(strBuilderReqHeader.toString());
        } catch (HttpMalformedHeaderException headerEx) {
            LOGGER.warn(
                    "Failed to create HTTP Request Header for HAR entry. \n {}",
                    headerEx.getMessage());
            return null;
        }
        return new HttpMessage(header, new HttpRequestBody(strBuilderReqBody.toString()));
    }

    public static HarLog createZapHarLog() {
        ZapHarCreator harCreator =
                new ZapHarCreator(Constant.PROGRAM_NAME, Constant.PROGRAM_VERSION);
        HarLog log = new HarLog();
        log.setCreator(harCreator);
        return log;
    }

    /**
     * Creates a {@code HarEntry} from the given message.
     *
     * @param httpMessage the HTTP message.
     * @return the {@code HarEntry}, never {@code null}.
     */
    public static HarEntry createHarEntry(HttpMessage httpMessage) {
        HarTiming timings = new ZapHarTiming(0, 0, httpMessage.getTimeElapsedMillis());

        HarEntry entry =
                new ZapHarEntry(
                        new Date(httpMessage.getTimeSentMillis()),
                        httpMessage.getTimeElapsedMillis(),
                        createHarRequest(httpMessage),
                        createHarResponse(httpMessage),
                        null,
                        timings);
        entry.setStartedDateTime(new Date(httpMessage.getTimeSentMillis()));
        return entry;
    }

    public static HarRequest createHarRequest(HttpMessage httpMessage) {
        HttpRequestHeader requestHeader = httpMessage.getRequestHeader();

        List<HarCookie> harCookies = new ArrayList<>();
        try {
            for (HttpCookie cookie : requestHeader.getHttpCookies()) {
                harCookies.add(new ZapHarCookie(cookie.getName(), cookie.getValue()));
            }
        } catch (IllegalArgumentException e) {
            LOGGER.warn(
                    "Ignoring cookies for HAR (\"request\") \"cookies\" list. Request contains invalid cookie: {}",
                    e.getMessage());
        }

        List<HarQueryParam> harQueryString = new ArrayList<>();
        for (HtmlParameter param : httpMessage.getUrlParams()) {
            harQueryString.add(new ZapHarQueryParam(param.getName(), param.getValue()));
        }

        HarPostData harPostData = null;
        HttpRequestBody requestBody = httpMessage.getRequestBody();
        if (requestBody.length() >= 0) {
            List<HarPostDataParam> params = new ArrayList<>();
            String text = "";

            String contentType = requestHeader.getHeader(HttpHeader.CONTENT_TYPE);
            if (contentType == null) {
                contentType = "";
                text = requestBody.toString();
            } else {
                if (StringUtils.startsWithIgnoreCase(
                        contentType.trim(), HttpHeader.FORM_URLENCODED_CONTENT_TYPE)) {
                    for (HtmlParameter param : httpMessage.getFormParams()) {
                        params.add(new ZapHarPostDataParam(param.getName(), param.getValue()));
                    }
                } else {
                    text = requestBody.toString();
                }
            }
            harPostData = new ZapHarPostData(contentType, params, text, null);
        }

        HttpMethod method = HttpMethod.valueOf(requestHeader.getMethod().toUpperCase(Locale.ROOT));
        return new ZapHarRequest(
                method,
                requestHeader.getURI().toString(),
                requestHeader.getVersion(),
                harCookies,
                createHarHeaders(requestHeader),
                harQueryString,
                harPostData,
                (long) requestHeader.toString().length(),
                (long) httpMessage.getRequestBody().length(),
                null);
    }

    public static HarResponse createHarResponse(HttpMessage httpMessage) {
        HttpResponseHeader responseHeader = httpMessage.getResponseHeader();
        List<HarCookie> harCookies = new ArrayList<>();

        long whenCreated = System.currentTimeMillis();
        for (HttpCookie cookie :
                responseHeader.getHttpCookies(httpMessage.getRequestHeader().getHostName())) {
            Date expires;
            if (cookie.getVersion() == 0) {
                expires = new Date(whenCreated + (cookie.getMaxAge() * 1000));
            } else {
                expires =
                        new Date(
                                httpMessage.getTimeSentMillis()
                                        + httpMessage.getTimeElapsedMillis()
                                        + (cookie.getMaxAge() * 1000));
            }

            harCookies.add(
                    new ZapHarCookie(
                            cookie.getName(),
                            cookie.getValue(),
                            cookie.getPath(),
                            cookie.getDomain(),
                            expires,
                            cookie.isHttpOnly(),
                            cookie.getSecure(),
                            null));
        }

        String text = null;
        String encoding = null;
        String contentType = responseHeader.getHeader(HttpHeader.CONTENT_TYPE);
        if (contentType == null) {
            contentType = "";
        } else if (!contentType.isEmpty()) {
            String lcContentType = contentType.toLowerCase(Locale.ROOT);
            final int pos = lcContentType.indexOf(';');
            if (pos != -1) {
                lcContentType = lcContentType.substring(0, pos).trim();
            }

            if (!lcContentType.startsWith("text")) {
                encoding = "base64";
                text = Base64.getEncoder().encodeToString(httpMessage.getResponseBody().getBytes());
            } else {
                text = httpMessage.getResponseBody().toString();
            }
        }

        HarContent harContent =
                new ZapHarContent(
                        (long) httpMessage.getResponseBody().length(),
                        (long) 0,
                        contentType,
                        text,
                        encoding,
                        null);

        String redirectUrl = responseHeader.getHeader(HttpHeader.LOCATION);

        return new ZapHarResponse(
                HttpStatus.byCode(responseHeader.getStatusCode()),
                responseHeader.getReasonPhrase(),
                responseHeader.getVersion(),
                harCookies,
                createHarHeaders(responseHeader),
                harContent,
                redirectUrl == null ? "" : redirectUrl,
                (long) responseHeader.toString().length(),
                (long) httpMessage.getResponseBody().length(),
                null);
    }

    public static List<HarHeader> createHarHeaders(HttpHeader httpHeader) {
        List<HarHeader> harHeaders = new ArrayList<>();
        List<HttpHeaderField> headers = httpHeader.getHeaders();
        for (HttpHeaderField headerField : headers) {
            harHeaders.add(new ZapHarHeader(headerField.getName(), headerField.getValue()));
        }
        return harHeaders;
    }
}

class ZapHarCreator extends HarCreatorBrowser {
    ZapHarCreator(String name, String version) {
        this.setName(name);
        this.setVersion(version);
    }
}

class ZapHarHeader extends HarHeader {
    ZapHarHeader(String name, String value) {
        this.setName(name);
        this.setValue(value);
    }
}

class ZapHarCookie extends HarCookie {

    ZapHarCookie(String name, String value) {
        this.setName(name);
        this.setValue(value);
    }

    ZapHarCookie(
            String name,
            String value,
            String path,
            String domain,
            Date expiry,
            boolean httpOnly,
            boolean secure,
            String comment) {
        this.setName(name);
        this.setValue(value);
        this.setPath(path);
        this.setDomain(domain);
        this.setExpires(expiry);
        this.setHttpOnly(httpOnly);
        this.setSecure(secure);
        this.setComment(comment);
    }
}

class ZapHarQueryParam extends HarQueryParam {
    ZapHarQueryParam(String name, String value) {
        this.setName(name);
        this.setValue(value);
    }
}

class ZapHarPostDataParam extends HarPostDataParam {
    ZapHarPostDataParam(String name, String value) {
        this.setName(name);
        this.setValue(value);
    }
}

class ZapHarPostData extends HarPostData {

    ZapHarPostData(String contentType, List<HarPostDataParam> params, String text, String comment) {
        this.setMimeType(contentType);
        this.setParams(params);
        this.setText(text);
        this.setComment(comment);
    }
}

class ZapHarRequest extends HarRequest {

    ZapHarRequest(
            HttpMethod method,
            String url,
            String httpVersion,
            List<HarCookie> cookies,
            List<HarHeader> headers,
            List<HarQueryParam> queryParams,
            HarPostData harPostData,
            Long headerSize,
            Long bodySize,
            String comment) {
        this.setMethod(method);
        this.setUrl(url);
        this.setHttpVersion(httpVersion);
        this.setCookies(cookies);
        this.setHeaders(headers);
        this.setQueryString(queryParams);
        this.setPostData(harPostData);
        this.setHeadersSize(headerSize);
        this.setBodySize(bodySize);
        this.setComment(comment);
    }
}

class ZapHarResponse extends HarResponse {

    ZapHarResponse(
            HttpStatus status,
            String statusText,
            String httpVersion,
            List<HarCookie> cookies,
            List<HarHeader> headers,
            HarContent content,
            String redirectUrl,
            Long headerSize,
            Long bodySize,
            String comment) {
        this.setStatus(status.getCode());
        this.setStatusText(statusText);
        this.setHttpVersion(httpVersion);
        this.setCookies(cookies);
        this.setHeaders(headers);
        this.setContent(content);
        this.setRedirectURL(redirectUrl);
        this.setHeadersSize(headerSize);
        this.setBodySize(bodySize);
        this.setComment(comment);
    }
}

class ZapHarContent extends HarContent {

    ZapHarContent(
            Long size,
            Long compression,
            String mimeType,
            String text,
            String encoding,
            String comment) {
        this.setSize(size);
        this.setCompression(compression);
        this.setMimeType(mimeType);
        this.setText(text);
        this.setEncoding(encoding);
        this.setComment(comment);
    }
}

class ZapHarEntry extends HarEntry {

    ZapHarEntry(
            Date startedDateTime,
            int time,
            HarRequest request,
            HarResponse response,
            HarCache cache,
            HarTiming timings) {
        this.setStartedDateTime(startedDateTime);
        this.setTime(time);
        this.setRequest(request);
        this.setResponse(response);
        this.setCache(cache);
        this.setTimings(timings);
    }
}

class ZapHarTiming extends HarTiming {

    ZapHarTiming(int send, int wait, int receive) {
        this.setSend(send);
        this.setWait(wait);
        this.setReceive(receive);
    }
}
