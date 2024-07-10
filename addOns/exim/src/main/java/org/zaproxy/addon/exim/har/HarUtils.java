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
    // TODO: The custom fields from the core class:
    // /zap/src/main/java/org/zaproxy/zap/utils/HarUtils.java
    // needs to be migrated to accommodate har writing/creation
    private static final Logger LOGGER = LogManager.getLogger(HarUtils.class);

    private HarUtils() {}

    public static HarLog createZapHarLog() {
        HarCreatorBrowser harCreator = new HarCreatorBrowser();
        harCreator.setName(Constant.PROGRAM_NAME);
        harCreator.setVersion(Constant.PROGRAM_VERSION);
        HarLog log = new HarLog();
        log.setCreator(harCreator);
        return log;
    }

    public static HttpMessage createHttpMessage(HarRequest harRequest)
            throws HttpMalformedHeaderException {
        StringBuilder strBuilderReqHeader = new StringBuilder();

        strBuilderReqHeader
                .append(harRequest.getMethod())
                .append(' ')
                .append(harRequest.getUrl())
                .append(' ')
                .append(harRequest.getHttpVersion())
                .append(HttpHeader.CRLF);

        for (HarHeader harHeader : harRequest.getHeaders()) {
            strBuilderReqHeader
                    .append(harHeader.getName())
                    .append(": ")
                    .append(harHeader.getValue())
                    .append(HttpHeader.CRLF);
        }
        strBuilderReqHeader.append(HttpHeader.CRLF);

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
                    "Failed to create HTTP Request Header for HAR entry.\n{}",
                    headerEx.getMessage());
            return null;
        }
        return new HttpMessage(header, new HttpRequestBody(strBuilderReqBody.toString()));
    }

    /**
     * Creates a {@code HarEntry} from the given message.
     *
     * @param httpMessage the HTTP message.
     * @return the {@code HarEntry}, never {@code null}.
     */
    public static HarEntry createHarEntry(HttpMessage httpMessage) {
        HarTiming newTimings = new HarTiming();
        newTimings.setSend(0);
        newTimings.setWait(0);
        newTimings.setReceive(httpMessage.getTimeElapsedMillis());

        HarEntry newEntry = new HarEntry();
        newEntry.setStartedDateTime(new Date(httpMessage.getTimeSentMillis()));
        newEntry.setTime(httpMessage.getTimeElapsedMillis());
        newEntry.setRequest(createHarRequest(httpMessage));
        newEntry.setResponse(createHarResponse(httpMessage));
        newEntry.setTimings(newTimings);
        return newEntry;
    }

    public static HarRequest createHarRequest(HttpMessage httpMessage) {
        HttpRequestHeader requestHeader = httpMessage.getRequestHeader();

        List<HarCookie> harCookies = new ArrayList<>();
        try {
            for (HttpCookie cookie : requestHeader.getHttpCookies()) {
                HarCookie newCookie = new HarCookie();
                newCookie.setName(cookie.getName());
                newCookie.setValue(cookie.getValue());
                harCookies.add(newCookie);
            }
        } catch (IllegalArgumentException e) {
            LOGGER.warn(
                    "Ignoring cookies for HAR (\"request\") \"cookies\" list. Request contains invalid cookie: {}",
                    e.getMessage());
        }

        List<HarQueryParam> harQueryString = new ArrayList<>();
        for (HtmlParameter param : httpMessage.getUrlParams()) {
            HarQueryParam newQueryParam = new HarQueryParam();
            newQueryParam.setName(param.getName());
            newQueryParam.setValue(param.getValue());
            harQueryString.add(newQueryParam);
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
                        HarPostDataParam newPostParam = new HarPostDataParam();
                        newPostParam.setName(param.getName());
                        newPostParam.setValue(param.getValue());
                        params.add(newPostParam);
                    }
                } else {
                    text = requestBody.toString();
                }
            }
            HarPostData newPostData = new HarPostData();
            newPostData.setMimeType(contentType);
            newPostData.setParams(params);
            newPostData.setText(text);
        }

        HttpMethod method = HttpMethod.valueOf(requestHeader.getMethod().toUpperCase(Locale.ROOT));
        HarRequest newHarRequest = new HarRequest();
        newHarRequest.setMethod(method);
        newHarRequest.setUrl(requestHeader.getURI().toString());
        newHarRequest.setHttpVersion(requestHeader.getVersion());
        newHarRequest.setCookies(harCookies);
        newHarRequest.setHeaders(createHarHeaders(requestHeader));
        newHarRequest.setQueryString(harQueryString);
        newHarRequest.setPostData(harPostData);
        newHarRequest.setHeadersSize((long) requestHeader.toString().length());
        newHarRequest.setBodySize((long) httpMessage.getRequestBody().length());
        return newHarRequest;
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

            HarCookie newCookie = new HarCookie();
            newCookie.setName(cookie.getName());
            newCookie.setValue(cookie.getValue());
            newCookie.setPath(cookie.getPath());
            newCookie.setDomain(cookie.getDomain());
            newCookie.setExpires(expires);
            newCookie.setHttpOnly(cookie.isHttpOnly());
            newCookie.setSecure(cookie.getSecure());
            harCookies.add(newCookie);
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

        HarContent newHarContent = new HarContent();
        newHarContent.setSize((long) httpMessage.getResponseBody().length());
        newHarContent.setCompression((long) 0);
        newHarContent.setMimeType(contentType);
        newHarContent.setText(text);
        newHarContent.setEncoding(encoding);

        String redirectUrl = responseHeader.getHeader(HttpHeader.LOCATION);

        HarResponse newHarResponse = new HarResponse();
        newHarResponse.setStatus(HttpStatus.byCode(responseHeader.getStatusCode()).getCode());
        newHarResponse.setStatusText(responseHeader.getReasonPhrase());
        newHarResponse.setHttpVersion(responseHeader.getVersion());
        newHarResponse.setCookies(harCookies);
        newHarResponse.setHeaders(createHarHeaders(responseHeader));
        newHarResponse.setContent(newHarContent);
        newHarResponse.setRedirectURL(redirectUrl == null ? "" : redirectUrl);
        newHarResponse.setHeadersSize((long) responseHeader.toString().length());
        newHarResponse.setBodySize((long) httpMessage.getResponseBody().length());
        return newHarResponse;
    }

    public static List<HarHeader> createHarHeaders(HttpHeader httpHeader) {
        List<HarHeader> harHeaders = new ArrayList<>();
        List<HttpHeaderField> headers = httpHeader.getHeaders();
        for (HttpHeaderField headerField : headers) {
            HarHeader newHeader = new HarHeader();
            newHeader.setName(headerField.getName());
            newHeader.setValue(headerField.getValue());
            harHeaders.add(newHeader);
        }
        return harHeaders;
    }
}
