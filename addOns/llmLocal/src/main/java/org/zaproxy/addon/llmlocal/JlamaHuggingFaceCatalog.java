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
package org.zaproxy.addon.llmlocal;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpSender;

/** Lists HuggingFace models for a given author via the Hub API. */
public final class JlamaHuggingFaceCatalog {

    private static final Logger LOGGER = LogManager.getLogger(JlamaHuggingFaceCatalog.class);

    static final String DEFAULT_AUTHOR = "tjake";

    private static final int DEFAULT_LIMIT = 100;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JlamaHuggingFaceCatalog() {}

    /**
     * Lists models published by {@value #DEFAULT_AUTHOR}, preferring pre-quantized Jlama builds.
     *
     * @param httpSender the sender used for the Hub request
     * @return model ids in {@code owner/name} form
     * @throws IOException if the catalog cannot be fetched or parsed
     */
    public static List<String> listTjakeModels(HttpSender httpSender) throws IOException {
        return listModels(httpSender, DEFAULT_AUTHOR, DEFAULT_LIMIT);
    }

    /**
     * Lists models for {@code author} from the HuggingFace Hub API.
     *
     * @param httpSender the sender used for the Hub request
     * @param author the HuggingFace author / org
     * @param limit maximum number of models to request
     * @return model ids in {@code owner/name} form, preferred Jlama builds first
     * @throws IOException if the catalog cannot be fetched or parsed
     */
    public static List<String> listModels(HttpSender httpSender, String author, int limit)
            throws IOException {
        String owner = StringUtils.trimToEmpty(author);
        if (owner.isEmpty()) {
            throw new IllegalArgumentException("author is required");
        }
        if (httpSender == null) {
            throw new IllegalArgumentException("httpSender is required");
        }

        String url =
                "https://huggingface.co/api/models?author="
                        + owner
                        + "&limit="
                        + Math.max(1, limit);
        HttpMessage message;
        try {
            message = new HttpMessage(new URI(url, true));
            message.getRequestHeader().setMethod(HttpRequestHeader.GET);
            httpSender.sendAndReceive(message);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("HuggingFace catalog request failed: " + e.getMessage(), e);
        }

        int status = message.getResponseHeader().getStatusCode();
        if (status < 200 || status >= 300) {
            throw new IOException("HuggingFace catalog request failed with HTTP " + status);
        }

        return parseModelIds(message.getResponseBody().toString());
    }

    /**
     * Parses a HuggingFace models API JSON array into model ids, sorting preferred Jlama builds
     * first.
     *
     * @param json the response body
     * @return model ids
     * @throws IOException if the JSON cannot be parsed
     */
    static List<String> parseModelIds(String json) throws IOException {
        JsonNode root = MAPPER.readTree(json);
        if (root == null || !root.isArray()) {
            throw new IOException("Unexpected HuggingFace catalog response");
        }

        List<String> ids = new ArrayList<>();
        for (JsonNode node : root) {
            String id = textOrNull(node, "id");
            if (id == null) {
                id = textOrNull(node, "modelId");
            }
            if (StringUtils.isNotBlank(id)) {
                ids.add(id.trim());
            }
        }

        ids.sort(
                Comparator.comparing((String id) -> !isPreferredJlamaModel(id))
                        .thenComparing(String::compareToIgnoreCase));
        LOGGER.debug("Parsed {} HuggingFace model ids", ids.size());
        return ids;
    }

    static boolean isPreferredJlamaModel(String modelId) {
        String lower = StringUtils.defaultString(modelId).toLowerCase(Locale.ROOT);
        return lower.contains("jlama") || lower.contains("jq4");
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }
}
