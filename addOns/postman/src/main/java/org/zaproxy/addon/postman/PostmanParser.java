/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.postman;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.TypeFactory;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.io.FileUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.postman.models.AbstractItem;
import org.zaproxy.addon.postman.models.Body;
import org.zaproxy.addon.postman.models.Body.FormData;
import org.zaproxy.addon.postman.models.Body.GraphQl;
import org.zaproxy.addon.postman.models.Item;
import org.zaproxy.addon.postman.models.ItemGroup;
import org.zaproxy.addon.postman.models.KeyValueData;
import org.zaproxy.addon.postman.models.PostmanCollection;
import org.zaproxy.addon.postman.models.Request;
import org.zaproxy.addon.postman.models.Request.Url;

public class PostmanParser {

    Requestor requestor;
    private static final String MESSAGE_PREFIX = "postman.importfrom";

    private static final Map<String, String> CONTENT_TYPE_MAP =
            Map.of(
                    "html", "text/html",
                    "javascript", "application/javascript",
                    "json", "application/json",
                    "xml", "application/xml");

    public PostmanParser() {
        requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR, new HistoryPersister());
    }

    public void importFromFile(final String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new FileNotFoundException(
                    Constant.messages.getString(MESSAGE_PREFIX + "file.filenotfound", filePath));
        }
        if (!file.canRead() || !file.isFile()) {
            throw new IOException(
                    Constant.messages.getString(MESSAGE_PREFIX + "file.cannotreadfile", filePath));
        }

        String collectionJson = FileUtils.readFileToString(file, StandardCharsets.UTF_8);
        importCollection(collectionJson);
    }

    public void importFromUrl(final String url) throws IllegalArgumentException, IOException {
        if (url.isEmpty()) {
            throw new IllegalArgumentException(
                    Constant.messages.getString(MESSAGE_PREFIX + "url.emptyurl"));
        }

        URI uri = new URI(url, false);

        if (!isSupportedScheme(uri.getScheme())) {
            throw new IllegalArgumentException(
                    Constant.messages.getString(MESSAGE_PREFIX + "url.unsupportedscheme", url));
        }

        String collectionJson = requestor.getResponseBody(uri);
        importCollection(collectionJson);
    }

    public void importCollection(String collection) throws JsonProcessingException {
        PostmanCollection postmanCollection = parse(collection);

        List<HttpMessage> httpMessages = new ArrayList<>();
        extractHttpMessages(postmanCollection.getItem(), httpMessages);

        requestor.run(httpMessages);
    }

    public PostmanCollection parse(String collectionJson) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setTypeFactory(
                TypeFactory.defaultInstance()
                        .withClassLoader(PostmanParser.class.getClassLoader()));
        return objectMapper.readValue(collectionJson, PostmanCollection.class);
    }

    static void extractHttpMessages(List<AbstractItem> items, List<HttpMessage> httpMessages) {
        for (AbstractItem item : items) {
            if (item instanceof Item) {
                HttpMessage httpMessage = extractHttpMessage((Item) item);
                if (httpMessage != null) {
                    httpMessages.add(httpMessage);
                }
            } else if (item instanceof ItemGroup) {
                extractHttpMessages(((ItemGroup) item).getItem(), httpMessages);
            }
        }
    }

    private static boolean isSupportedScheme(String scheme) {
        return "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
    }

    private static boolean isContentTypeAlreadySet(List<KeyValueData> headers) {
        if (headers != null) {
            for (KeyValueData header : headers) {
                if (header.getKey().equalsIgnoreCase(HttpHeader.CONTENT_TYPE)) {
                    return true;
                }
            }
        }
        return false;
    }

    static HttpMessage extractHttpMessage(Item item) {
        Request request = item.getRequest();
        if (request == null) {
            return null;
        }

        Url url = request.getUrl();
        if (url == null) {
            return null;
        }

        HttpMessage httpMessage;
        try {
            String rawUrl = url.getRaw();
            httpMessage = new HttpMessage(new URI(rawUrl, false));
        } catch (URIException | HttpMalformedHeaderException | NullPointerException e) {
            return null;
        }

        httpMessage.getRequestHeader().setMethod(request.getMethod());

        List<KeyValueData> headers = request.getHeader();
        if (headers != null) {
            for (KeyValueData header : request.getHeader()) {
                if (!header.isDisabled()) {
                    httpMessage.getRequestHeader().setHeader(header.getKey(), header.getValue());
                }
            }
        }

        Body body = request.getBody();
        if (body == null || body.isDisabled()) {
            return httpMessage;
        }

        String mode = body.getMode();
        if (mode == null) {
            return httpMessage;
        }

        String bodyContent = "";
        String contentType = "";

        if (mode.equals(Body.RAW)) {
            if (body.getRaw() == null) {
                return httpMessage;
            }

            contentType = "text/plain";

            if (body.getOptions() != null && body.getOptions().getRaw() != null) {
                String language = body.getOptions().getRaw().getLanguage();

                if (language != null) {
                    contentType =
                            CONTENT_TYPE_MAP.getOrDefault(
                                    language.toLowerCase(Locale.ROOT), "text/html");
                }
            }

            bodyContent = body.getRaw();
        } else if (mode.equals(Body.URL_ENCODED)) {
            if (body.getUrlencoded() == null) {
                return httpMessage;
            }

            contentType = HttpHeader.FORM_URLENCODED_CONTENT_TYPE;

            StringBuilder urlencodedBodySB = new StringBuilder();

            for (KeyValueData data : body.getUrlencoded()) {
                if (!data.isDisabled()) {
                    if (urlencodedBodySB.length() > 0) {
                        urlencodedBodySB.append('&');
                    }
                    try {
                        urlencodedBodySB
                                .append(
                                        URLEncoder.encode(
                                                data.getKey(), StandardCharsets.UTF_8.name()))
                                .append('=')
                                .append(
                                        URLEncoder.encode(
                                                data.getValue(), StandardCharsets.UTF_8.name()));
                    } catch (UnsupportedEncodingException e) {
                    }
                }
            }

            bodyContent = urlencodedBodySB.toString();
        } else if (mode.equals(Body.FORM_DATA)) {
            if (body.getFormData() == null) {
                return httpMessage;
            }

            String boundary = "----" + System.currentTimeMillis();

            contentType = "multipart/form-data; boundary=" + boundary;

            StringBuilder formDataBody = new StringBuilder();
            for (FormData formData : body.getFormData()) {
                if (!formData.isDisabled()) {
                    formDataBody
                            .append(generateMultiPartBody(formData, boundary))
                            .append(HttpHeader.CRLF);
                }
            }

            formDataBody.append("--").append(boundary).append("--").append(HttpHeader.CRLF);

            bodyContent = formDataBody.toString();
        } else if (mode.equals(Body.FILE)) {
            if (body.getFile() == null) {
                return httpMessage;
            }

            String src = body.getFile().getSrc();

            contentType = getFileContentType(src);

            try {
                bodyContent = FileUtils.readFileToString(new File(src), StandardCharsets.UTF_8);
            } catch (IOException e1) {
            }
        } else if (mode.equals(Body.GRAPHQL)) {
            if (body.getGraphQl() == null) {
                return httpMessage;
            }

            contentType = HttpHeader.JSON_CONTENT_TYPE;

            GraphQl graphQlBody = body.getGraphQl();
            String query = graphQlBody.getQuery().replaceAll("\r\n", "\\\\r\\\\n");
            String variables = graphQlBody.getVariables().replaceAll("\\s", "");

            bodyContent = String.format("{\"query\":\"%s\", \"variables\":%s}", query, variables);
        }

        if (!isContentTypeAlreadySet(request.getHeader())) {
            httpMessage.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, contentType);
        }

        httpMessage.getRequestBody().setBody(bodyContent.toString());
        httpMessage.getRequestHeader().setContentLength(httpMessage.getRequestBody().length());

        return httpMessage;
    }

    private static String generateMultiPartBody(FormData formData, String boundary) {
        StringBuilder multipartData = new StringBuilder();

        multipartData.append("--").append(boundary).append(HttpHeader.CRLF);
        multipartData
                .append("Content-Disposition: form-data; name=\"")
                .append(formData.getKey())
                .append('"');

        if (Body.FILE.equals(formData.getType())) {
            File file = new File(formData.getSrc());
            if (!file.exists() || !file.canRead() || !file.isFile()) {
                return "";
            }

            multipartData
                    .append("; filename=\"")
                    .append(file.getName())
                    .append('"')
                    .append(HttpHeader.CRLF);

            String propertyContentType = getFileContentType(formData.getSrc());
            if (!propertyContentType.isEmpty()) {
                multipartData
                        .append(HttpHeader.CONTENT_TYPE)
                        .append(": ")
                        .append(propertyContentType)
                        .append(HttpHeader.CRLF);
            }

            multipartData.append(HttpHeader.CRLF);

            try {
                String defn = FileUtils.readFileToString(file, StandardCharsets.UTF_8);
                multipartData.append(defn);
            } catch (IOException e) {
                return "";
            }
        } else {
            multipartData
                    .append(HttpHeader.CRLF)
                    .append(HttpHeader.CRLF)
                    .append(formData.getValue());
        }

        return multipartData.toString();
    }

    private static String getFileContentType(String value) {
        try {
            String osAppropriatePath = value.startsWith("/") ? value.substring(1) : value;
            return Files.probeContentType(Paths.get(osAppropriatePath));
        } catch (IOException e) {
            return "";
        }
    }
}
