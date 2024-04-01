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
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.postman.models.AbstractItem;
import org.zaproxy.addon.postman.models.Body;
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

    private static final String IMPORT_FORMAT_ERROR = "postman.import.error.format";
    private static final String IMPORT_WARNING = "postman.import.warning";

    private static final Map<String, String> CONTENT_TYPE_MAP =
            Map.of(
                    "html", "text/html",
                    "javascript", "application/javascript",
                    "json", "application/json",
                    "xml", "application/xml");

    public PostmanParser() {
        requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR, new HistoryPersister());
    }

    public boolean importFromFile(
            final String filePath, final String variables, final boolean initViaUi)
            throws IOException {
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
        return importCollection(collectionJson, variables, initViaUi);
    }

    public boolean importFromUrl(final String url, final String variables, final boolean initViaUi)
            throws IllegalArgumentException, IOException {
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
        return importCollection(collectionJson, variables, initViaUi);
    }

    List<HttpMessage> getHttpMessages(
            String collection, final String variables, List<String> errors)
            throws JsonProcessingException {
        collection = replaceVariables(collection, variables);

        PostmanCollection postmanCollection = parse(collection);
        List<HttpMessage> httpMessages = new ArrayList<>();

        extractHttpMessages(
                postmanCollection.getItem(), httpMessages, errors, postmanCollection.getVariable());
        if (httpMessages.isEmpty()) {
            errors.add(Constant.messages.getString("postman.import.error.noItem"));
        }
        return httpMessages;
    }

    public boolean importCollection(
            String collection, final String variables, final boolean initViaUi)
            throws JsonProcessingException {
        List<String> errors = new ArrayList<>();
        List<HttpMessage> httpMessages = getHttpMessages(collection, variables, errors);

        requestor.run(httpMessages, errors);

        outputErrors(errors, initViaUi);

        return errors.isEmpty();
    }

    private static void outputErrors(List<String> errors, final boolean initViaUi) {
        if (initViaUi && errors != null) {
            for (String error : errors) {
                View.getSingleton().getOutputPanel().append(error + "\n");
            }
        }
    }

    private static Map<String, String> parseVariables(String variables) {
        Map<String, String> variableMap = new HashMap<>();
        String[] pairs = variables.split(",");
        for (String pair : pairs) {
            String[] parts = pair.split("=", 2);
            if (parts.length == 2) {
                variableMap.put(parts[0], StringEscapeUtils.escapeJson(parts[1]));
            }
        }
        return variableMap;
    }

    static String replaceVariables(String collection, String variables) {
        Map<String, String> variableMap = parseVariables(variables);

        for (Map.Entry<String, String> variableEntry : variableMap.entrySet()) {
            String variable = "{{" + variableEntry.getKey() + "}}";
            String value = variableEntry.getValue();
            collection = collection.replace(variable, value);
        }
        return collection;
    }

    static String replaceVariables(
            String string,
            List<KeyValueData> variables,
            String variablePrefix,
            String variableSuffix) {
        if (string != null && variables != null) {
            for (KeyValueData variableEntry : variables) {
                String variable = variablePrefix + variableEntry.getKey() + variableSuffix;
                String value = variableEntry.getValue();
                string = string.replace(variable, value);
            }
        }
        return string;
    }

    static String replaceJsonVariables(String value, List<KeyValueData> variables) {
        return replaceVariables(value, variables, "{{", "}}");
    }

    static String replaceJsonPathVariables(String value, List<KeyValueData> variables) {
        return replaceVariables(value, variables, ":", "");
    }

    public PostmanCollection parse(String collectionJson) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setTypeFactory(
                TypeFactory.defaultInstance()
                        .withClassLoader(PostmanParser.class.getClassLoader()));
        return objectMapper.readValue(collectionJson, PostmanCollection.class);
    }

    static void extractHttpMessages(List<AbstractItem> items, List<HttpMessage> httpMessages) {
        extractHttpMessages(items, httpMessages, new ArrayList<>(), null);
    }

    static List<KeyValueData> getCombinedVarList(
            List<KeyValueData> firstList, List<KeyValueData> secondList) {

        List<KeyValueData> finalList = new ArrayList<>();

        if (firstList != null) {
            finalList.addAll(firstList);
        }

        if (secondList != null) {
            finalList.addAll(secondList);
        }
        return finalList;
    }

    static void extractHttpMessages(
            List<AbstractItem> items,
            List<HttpMessage> httpMessages,
            List<String> errors,
            List<KeyValueData> parentVariables) {
        if (items != null) {
            for (AbstractItem item : items) {
                if (item instanceof Item) {
                    HttpMessage httpMessage =
                            extractHttpMessage((Item) item, errors, parentVariables);
                    if (httpMessage != null) {
                        httpMessages.add(httpMessage);
                    }
                } else if (item instanceof ItemGroup) {
                    ItemGroup itemGroup = (ItemGroup) item;

                    extractHttpMessages(
                            itemGroup.getItem(),
                            httpMessages,
                            errors,
                            getCombinedVarList(itemGroup.getVariable(), parentVariables));
                }
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
        return extractHttpMessage(item, new ArrayList<>(), null);
    }

    static HttpMessage extractHttpMessage(
            Item item, List<String> errors, List<KeyValueData> parentVariables) {
        Request request = item.getRequest();
        if (request == null) {
            errors.add(
                    Constant.messages.getString(
                            IMPORT_FORMAT_ERROR,
                            item.getName(),
                            Constant.messages.getString("postman.import.errorMsg.reqNotPresent")));
            return null;
        }

        Url url = request.getUrl();
        if (url == null) {
            errors.add(
                    Constant.messages.getString(
                            IMPORT_FORMAT_ERROR,
                            item.getName(),
                            Constant.messages.getString("postman.import.errorMsg.urlNotPresent")));
            return null;
        }

        HttpMessage httpMessage;

        List<KeyValueData> allVariables = getCombinedVarList(parentVariables, item.getVariable());

        try {
            String rawUrl = replaceJsonVariables(url.getRaw(), allVariables);

            List<KeyValueData> urlVariables = url.getVariable();
            URI uri = new URI(rawUrl, false);

            String pathWithReplaceVars = replaceJsonPathVariables(uri.getPath(), urlVariables);
            uri.setPath(pathWithReplaceVars);

            httpMessage = new HttpMessage(uri);
        } catch (URIException | HttpMalformedHeaderException | NullPointerException e) {
            errors.add(
                    Constant.messages.getString(
                            IMPORT_FORMAT_ERROR,
                            item.getName(),
                            Constant.messages.getString("postman.import.errorMsg.rawInvalid")));
            return null;
        }

        String method = replaceJsonVariables(request.getMethod(), allVariables);
        httpMessage.getRequestHeader().setMethod(method);

        List<KeyValueData> headers = request.getHeader();
        if (headers != null) {
            for (KeyValueData header : request.getHeader()) {
                if (!header.isDisabled()) {
                    String key = replaceJsonVariables(header.getKey(), allVariables);
                    String value = replaceJsonVariables(header.getValue(), allVariables);
                    httpMessage.getRequestHeader().setHeader(key, value);
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
            for (KeyValueData formData : body.getFormData()) {
                if (!formData.isDisabled()) {
                    formDataBody
                            .append(
                                    generateMultiPartBody(
                                            formData, boundary, errors, item.getName()))
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

            contentType = getFileContentType(src, errors, item.getName());

            try {
                bodyContent = FileUtils.readFileToString(new File(src), StandardCharsets.UTF_8);
            } catch (IOException e1) {
                errors.add(
                        Constant.messages.getString(
                                IMPORT_WARNING,
                                item.getName(),
                                e1.getClass().getName() + ": " + e1.getMessage()));
            }
        } else if (mode.equals(Body.GRAPHQL)) {
            if (body.getGraphQl() == null) {
                return httpMessage;
            }

            contentType = HttpHeader.JSON_CONTENT_TYPE;

            GraphQl graphQlBody = body.getGraphQl();

            String query = graphQlBody.getQuery();
            String variables = graphQlBody.getVariables();

            if (variables != null && !variables.isEmpty()) {
                bodyContent =
                        String.format(
                                "{\"query\":\"%s\", \"variables\":%s}",
                                query.replaceAll("\r\n", "\\\\r\\\\n"),
                                variables.replaceAll("\\s", ""));
            } else {
                bodyContent =
                        String.format("{\"query\":\"%s\"}", query.replaceAll("\r\n", "\\\\r\\\\n"));
            }
        }

        if (!isContentTypeAlreadySet(request.getHeader())) {
            contentType = replaceJsonVariables(contentType, allVariables);
            httpMessage.getRequestHeader().setHeader(HttpHeader.CONTENT_TYPE, contentType);
        }

        bodyContent = replaceJsonVariables(bodyContent.toString(), allVariables);
        httpMessage.getRequestBody().setBody(bodyContent);

        httpMessage.getRequestHeader().setContentLength(httpMessage.getRequestBody().length());

        return httpMessage;
    }

    private static String generateMultiPartBody(
            KeyValueData formData, String boundary, List<String> errors, String itemName) {
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

            String propertyContentType = getFileContentType(formData.getSrc(), errors, itemName);
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
                errors.add(
                        Constant.messages.getString(
                                IMPORT_WARNING,
                                itemName,
                                "Could not read file: " + e.getMessage()));
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

    private static String getFileContentType(String value, List<String> errors, String itemName) {
        try {
            String osAppropriatePath = value.startsWith("/") ? value.substring(1) : value;
            return Files.probeContentType(Paths.get(osAppropriatePath));
        } catch (IOException e) {
            errors.add(
                    Constant.messages.getString(
                            IMPORT_WARNING,
                            itemName,
                            "Could not get content type of file - "
                                    + e.getClass().getName()
                                    + ": "
                                    + e.getMessage()));
            return "";
        }
    }
}
