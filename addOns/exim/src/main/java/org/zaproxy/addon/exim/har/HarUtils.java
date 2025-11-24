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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import de.sstoehr.harreader.model.HarContent;
import de.sstoehr.harreader.model.HarCookie;
import de.sstoehr.harreader.model.HarCreatorBrowser;
import de.sstoehr.harreader.model.HarEntry;
import de.sstoehr.harreader.model.HarHeader;
import de.sstoehr.harreader.model.HarLog;
import de.sstoehr.harreader.model.HarLog.HarLogBuilder;
import de.sstoehr.harreader.model.HarPostData;
import de.sstoehr.harreader.model.HarPostDataParam;
import de.sstoehr.harreader.model.HarQueryParam;
import de.sstoehr.harreader.model.HarRequest;
import de.sstoehr.harreader.model.HarResponse;
import de.sstoehr.harreader.model.HarTiming;
import de.sstoehr.harreader.model.HttpStatus;
import java.io.IOException;
import java.net.HttpCookie;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import org.apache.commons.lang3.Strings;
import org.apache.commons.text.StringEscapeUtils;
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
    private static final String BASE64_BODY_ENCODING = "base64";

    /**
     * The prefix for custom HAR fields produced by ZAP.
     *
     * @since 0.13.0
     */
    public static final String CUSTOM_FIELD_PREFIX = "_zap";

    /**
     * The name of the custom field that contains the message ID.
     *
     * @since 0.13.0
     */
    public static final String MESSAGE_ID_CUSTOM_FIELD = CUSTOM_FIELD_PREFIX + "MessageId";

    /**
     * The name of the custom field that contains the message type.
     *
     * @since 0.13.0
     */
    public static final String MESSAGE_TYPE_CUSTOM_FIELD = CUSTOM_FIELD_PREFIX + "MessageType";

    /**
     * The name of the custom field that contains the message note.
     *
     * @since 0.13.0
     */
    public static final String MESSAGE_NOTE_CUSTOM_FIELD = CUSTOM_FIELD_PREFIX + "MessageNote";

    private static final Logger LOGGER = LogManager.getLogger(HarUtils.class);

    public static final ObjectMapper JSON_MAPPER =
            JsonMapper.builder()
                    .addModule(new JavaTimeModule())
                    .configure(DeserializationFeature.ADJUST_DATES_TO_CONTEXT_TIME_ZONE, false)
                    .defaultPropertyInclusion(
                            JsonInclude.Value.construct(
                                    JsonInclude.Include.NON_DEFAULT,
                                    JsonInclude.Include.NON_DEFAULT))
                    .build();

    private static final ObjectWriter JSON_WRITER =
            JSON_MAPPER.writer(
                    new DefaultPrettyPrinter().withObjectIndenter(new DefaultIndenter("  ", "\n")));

    private HarUtils() {}

    public static HarLogBuilder createZapHarLog() {
        return HarLog.builder()
                .version("1.2")
                .creator(
                        HarCreatorBrowser.builder()
                                .name(Constant.PROGRAM_NAME)
                                .version(Constant.PROGRAM_VERSION)
                                .build());
    }

    /**
     * Creates an {@code HttpMessage} from the given HAR Request.
     *
     * @param harRequest the HAR request.
     * @return the HTTP message containing the given request.
     * @throws IOException if an error occurred while reading the HAR Request or creating the {@code
     *     HttpMessage}.
     * @since 0.13.0
     */
    public static HttpMessage createHttpMessage(String harRequest) throws IOException {
        return createHttpMessage(JSON_MAPPER.readValue(harRequest, HarEntry.class).request());
    }

    public static HttpMessage createHttpMessage(HarRequest harRequest)
            throws HttpMalformedHeaderException {
        StringBuilder strBuilderReqHeader = new StringBuilder();

        strBuilderReqHeader
                .append(harRequest.method())
                .append(' ')
                .append(harRequest.url())
                .append(' ')
                .append(harRequest.httpVersion())
                .append(HttpHeader.CRLF);

        for (HarHeader harHeader : harRequest.headers()) {
            strBuilderReqHeader
                    .append(harHeader.name())
                    .append(": ")
                    .append(harHeader.value())
                    .append(HttpHeader.CRLF);
        }
        strBuilderReqHeader.append(HttpHeader.CRLF);

        StringBuilder strBuilderReqBody = new StringBuilder();
        HarPostData harPostData = harRequest.postData();
        String text = harPostData.text();
        if (text != null && !text.isEmpty()) {
            strBuilderReqBody.append(harPostData.text());
        } else if (!harPostData.params().isEmpty()) {
            for (HarPostDataParam param : harPostData.params()) {
                if (strBuilderReqBody.length() > 0) {
                    strBuilderReqBody.append('&');
                }
                strBuilderReqBody.append(param.name()).append('=').append(param.value());
            }
        }

        return new HttpMessage(
                new HttpRequestHeader(strBuilderReqHeader.toString()),
                new HttpRequestBody(strBuilderReqBody.toString()));
    }

    /**
     * Creates an {@code HttpMessage} from the given HAR entry.
     *
     * @param harEntry the HAR entry.
     * @return the HTTP message containing the request and response from the HAR entry.
     * @throws HttpMalformedHeaderException if an error occurred while creating the request or
     *     response header from the HAR entry.
     * @since 0.13.0
     */
    public static HttpMessage createHttpMessage(HarEntry harEntry)
            throws HttpMalformedHeaderException {
        HttpMessage message = createHttpMessage(harEntry.request());

        message.setTimeSentMillis(
                Optional.ofNullable(harEntry.startedDateTime())
                        .map(ZonedDateTime::toInstant)
                        .map(Instant::toEpochMilli)
                        .orElse(0L));
        message.setTimeElapsedMillis(
                Optional.ofNullable(harEntry.timings().receive()).map(Long::intValue).orElse(0));

        setHttpResponse(harEntry.response(), message);

        return message;
    }

    private static void setHttpResponse(HarResponse harResponse, HttpMessage message)
            throws HttpMalformedHeaderException {
        // empty responses without status code are possible
        if (harResponse.status() == 0) {
            return;
        }

        StringBuilder strBuilderResHeader =
                new StringBuilder()
                        .append(harResponse.httpVersion())
                        .append(' ')
                        .append(harResponse.status())
                        .append(' ')
                        .append(harResponse.statusText())
                        .append(HttpHeader.CRLF);

        boolean mixedNewlineChars = false;
        for (HarHeader harHeader : harResponse.headers()) {
            String value = harHeader.value();
            if (value.contains("\n") || value.contains("\r")) {
                mixedNewlineChars = true;
                LOGGER.info(
                        "{}\n\t{} value contains CR or LF and is likely invalid (though it may have been successfully set to the message):\n\t{}",
                        message.getRequestHeader().getURI(),
                        harHeader.name(),
                        StringEscapeUtils.escapeJava(value));
            }
            strBuilderResHeader
                    .append(harHeader.name())
                    .append(": ")
                    .append(harHeader.value())
                    .append(HttpHeader.CRLF);
        }
        strBuilderResHeader.append(HttpHeader.CRLF);

        try {
            message.setResponseHeader(strBuilderResHeader.toString());
        } catch (HttpMalformedHeaderException e) {
            if (!mixedNewlineChars) {
                throw e;
            }
            LOGGER.info(
                    "Couldn't set response header for: {}", message.getRequestHeader().getURI());
        }
        message.setResponseFromTargetHost(true);

        HarContent harContent = harResponse.content();
        if (harContent != null) {
            if (BASE64_BODY_ENCODING.equals(harContent.encoding())) {
                var text = harContent.text();
                if (text != null)
                    try {
                        message.setResponseBody(Base64.getDecoder().decode(text));
                    } catch (IllegalArgumentException e) {
                        LOGGER.debug(
                                "Failed to base64 decode body {}. Setting as plain text.", text, e);
                        message.setResponseBody(text);
                    }
            } else {
                message.setResponseBody(harContent.text());
            }
        }
    }

    /**
     * Creates a {@code HarEntry} from the given message.
     *
     * @param httpMessage the HTTP message.
     * @return the {@code HarEntry}, never {@code null}.
     */
    public static HarEntry createHarEntry(HttpMessage httpMessage) {
        HarTiming newTimings =
                HarTiming.builder()
                        .send(0L)
                        .waitTime(0L)
                        .receive((long) httpMessage.getTimeElapsedMillis())
                        .build();

        HarEntry newEntry =
                HarEntry.builder()
                        .startedDateTime(createZonedDateTime(httpMessage.getTimeSentMillis()))
                        .time(httpMessage.getTimeElapsedMillis())
                        .request(createHarRequest(httpMessage))
                        .response(createHarResponse(httpMessage))
                        .timings(newTimings)
                        .build();
        addCustomFields(newEntry, httpMessage);
        return newEntry;
    }

    private static ZonedDateTime createZonedDateTime(long millis) {
        return ZonedDateTime.ofInstant(Instant.ofEpochMilli(millis), ZoneId.of("Z"));
    }

    private static void addCustomFields(HarEntry entry, HttpMessage message) {
        entry.setAdditionalField(MESSAGE_NOTE_CUSTOM_FIELD, message.getNote());
    }

    /**
     * Creates a {@code HarEntry} from the given message with additional custom fields for the
     * history ID/type and note.
     *
     * @param historyId the history ID of the HTTP message.
     * @param historyType the history type of the HTTP message.
     * @param httpMessage the HTTP message.
     * @return the {@code HarEntry}, never {@code null}.
     * @since 0.13.0
     * @see #MESSAGE_ID_CUSTOM_FIELD
     * @see #MESSAGE_TYPE_CUSTOM_FIELD
     * @see #MESSAGE_NOTE_CUSTOM_FIELD
     */
    public static HarEntry createHarEntry(int historyId, int historyType, HttpMessage httpMessage) {
        HarEntry entry = createHarEntry(httpMessage);
        entry.setAdditionalField(MESSAGE_ID_CUSTOM_FIELD, historyId);
        entry.setAdditionalField(MESSAGE_TYPE_CUSTOM_FIELD, historyType);
        addCustomFields(entry, httpMessage);
        return entry;
    }

    public static HarRequest createHarRequest(HttpMessage httpMessage) {
        HttpRequestHeader requestHeader = httpMessage.getRequestHeader();

        List<HarCookie> harCookies = new ArrayList<>();
        try {
            for (HttpCookie cookie : requestHeader.getHttpCookies()) {
                harCookies.add(
                        HarCookie.builder()
                                .name(cookie.getName())
                                .value(cookie.getValue())
                                .build());
            }
        } catch (IllegalArgumentException e) {
            LOGGER.warn(
                    "Ignoring cookies for HAR (\"request\") \"cookies\" list. Request contains invalid cookie: {}",
                    e.getMessage());
        }

        List<HarQueryParam> harQueryString = new ArrayList<>();
        for (HtmlParameter param : httpMessage.getUrlParams()) {
            harQueryString.add(
                    HarQueryParam.builder().name(param.getName()).value(param.getValue()).build());
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
                if (Strings.CI.startsWith(
                        contentType.trim(), HttpHeader.FORM_URLENCODED_CONTENT_TYPE)) {
                    for (HtmlParameter param : httpMessage.getFormParams()) {
                        params.add(
                                HarPostDataParam.builder()
                                        .name(param.getName())
                                        .value(param.getValue())
                                        .build());
                    }
                } else {
                    text = requestBody.toString();
                }
            }
            harPostData =
                    HarPostData.builder().mimeType(contentType).params(params).text(text).build();
        }

        return HarRequest.builder()
                .method(requestHeader.getMethod())
                .url(requestHeader.getURI().toString())
                .httpVersion(requestHeader.getVersion())
                .cookies(harCookies)
                .headers(createHarHeaders(requestHeader))
                .queryString(harQueryString)
                .postData(harPostData)
                .headersSize((long) requestHeader.toString().length())
                .bodySize((long) httpMessage.getRequestBody().length())
                .build();
    }

    public static HarResponse createHarResponse(HttpMessage httpMessage) {
        HttpResponseHeader responseHeader = httpMessage.getResponseHeader();
        List<HarCookie> harCookies = new ArrayList<>();

        long whenCreated = System.currentTimeMillis();
        for (HttpCookie cookie :
                responseHeader.getHttpCookies(httpMessage.getRequestHeader().getHostName())) {
            ZonedDateTime expires;
            if (cookie.getVersion() == 0) {
                expires = createZonedDateTime(whenCreated + (cookie.getMaxAge() * 1000));
            } else {
                expires =
                        createZonedDateTime(
                                httpMessage.getTimeSentMillis()
                                        + httpMessage.getTimeElapsedMillis()
                                        + (cookie.getMaxAge() * 1000));
            }

            harCookies.add(
                    HarCookie.builder()
                            .name(cookie.getName())
                            .value(cookie.getValue())
                            .path(cookie.getPath())
                            .domain(cookie.getDomain())
                            .expires(expires)
                            .httpOnly(cookie.isHttpOnly())
                            .secure(cookie.getSecure())
                            .build());
        }

        String text = null;
        String encoding = null;
        String contentType = responseHeader.getHeader(HttpHeader.CONTENT_TYPE);
        if (contentType == null || contentType.isEmpty()) {
            contentType = "";
            if (httpMessage.getResponseBody().length() != 0) {
                encoding = BASE64_BODY_ENCODING;
                text = Base64.getEncoder().encodeToString(httpMessage.getResponseBody().getBytes());
            }
        } else {
            String lcContentType = contentType.toLowerCase(Locale.ROOT);
            final int pos = lcContentType.indexOf(';');
            if (pos != -1) {
                lcContentType = lcContentType.substring(0, pos).trim();
            }

            if (!lcContentType.startsWith("text")) {
                encoding = BASE64_BODY_ENCODING;
                text = Base64.getEncoder().encodeToString(httpMessage.getResponseBody().getBytes());
            } else {
                text = httpMessage.getResponseBody().toString();
            }
        }

        HarContent newHarContent =
                HarContent.builder()
                        .size((long) httpMessage.getResponseBody().length())
                        .compression(0L)
                        .mimeType(contentType)
                        .text(text)
                        .encoding(encoding)
                        .build();

        String redirectUrl = responseHeader.getHeader(HttpHeader.LOCATION);

        return HarResponse.builder()
                .status(HttpStatus.byCode(responseHeader.getStatusCode()).getCode())
                .statusText(responseHeader.getReasonPhrase())
                .httpVersion(responseHeader.getVersion())
                .cookies(harCookies)
                .headers(createHarHeaders(responseHeader))
                .content(newHarContent)
                .redirectURL(redirectUrl == null ? "" : redirectUrl)
                .headersSize((long) responseHeader.toString().length())
                .bodySize((long) httpMessage.getResponseBody().length())
                .build();
    }

    public static List<HarHeader> createHarHeaders(HttpHeader httpHeader) {
        List<HarHeader> harHeaders = new ArrayList<>();
        List<HttpHeaderField> headers = httpHeader.getHeaders();
        for (HttpHeaderField headerField : headers) {
            harHeaders.add(
                    HarHeader.builder()
                            .name(headerField.getName())
                            .value(headerField.getValue())
                            .build());
        }
        return harHeaders;
    }

    /**
     * Converts the given {@code HarLog} into JSON and then to a byte array (UTF-8).
     *
     * @param harLog the {@code HarLog} to convert to JSON/bytes.
     * @return the bytes with the JSON conversion of the {@code HarLog}.
     * @throws IOException if failed to convert the {@code HarLog} into JSON.
     * @since 0.13.0
     */
    public static byte[] toJsonAsBytes(HarLog harLog) throws IOException {
        return JSON_WRITER.writeValueAsBytes(Map.of("log", harLog));
    }
}
