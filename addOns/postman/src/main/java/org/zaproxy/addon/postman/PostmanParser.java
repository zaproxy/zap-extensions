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
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.apache.commons.httpclient.URI;
import org.apache.commons.io.FileUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.postman.models.PostmanCollection;

public class PostmanParser {

    Requestor requestor;
    private static final String MESSAGE_PREFIX = "postman.importfrom";

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

        String defn = FileUtils.readFileToString(file, StandardCharsets.UTF_8);
        importDefinition(defn);
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

        String defn = requestor.getResponseBody(uri);
        importDefinition(defn);
    }

    public void importDefinition(String defn) throws JsonProcessingException {
        PostmanCollection postmanCollection = parse(defn);

        // TODO: Extract list of HttpMessage from PostmanCollection and send requests
    }

    public PostmanCollection parse(String defn) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(defn, PostmanCollection.class);
    }

    private static boolean isSupportedScheme(String scheme) {
        return "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
    }
}
