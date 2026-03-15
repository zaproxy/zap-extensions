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
package org.zaproxy.addon.mcp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Defines an MCP resource that can be read by clients.
 *
 * <p>Resources are discovered via {@code resources/list} and read via {@code resources/read}.
 */
public interface McpResource {

    public static final String MIME_TYPE = "application/json";
    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    /**
     * Returns the unique URI of the resource. Used as the identifier when reading the resource.
     *
     * @return the resource URI (e.g. {@code zap://alerts})
     */
    String getUri();

    /**
     * Returns a short name for the resource.
     *
     * @return the resource name
     */
    String getName();

    /**
     * Returns a human-readable description of the resource.
     *
     * @return the resource description
     */
    String getDescription();

    /**
     * Returns the MIME type of the resource content.
     *
     * @return the MIME type (e.g. {@code application/json})
     */
    default String getMimeType() {
        return MIME_TYPE;
    }

    /**
     * Returns the resource metadata for {@code resources/list}.
     *
     * @return an object with uri, name, description, mimeType
     */
    ObjectNode toListEntry();

    /**
     * Reads and returns the resource content.
     *
     * @return the resource content as a string
     */
    String readContent();

    /**
     * Reads and returns the resource content for the given URI.
     *
     * <p>Used for template-style resources (e.g. {@code zap://history/123}). The default
     * implementation delegates to {@link #readContent()}.
     *
     * @param uri the full URI that was requested
     * @return the resource content as a string
     */
    default String readContent(String uri) {
        return readContent();
    }

    public static String errorJson(String message) {
        ObjectNode node = OBJECT_MAPPER.createObjectNode();
        node.put("error", message);
        return node.toString();
    }
}
