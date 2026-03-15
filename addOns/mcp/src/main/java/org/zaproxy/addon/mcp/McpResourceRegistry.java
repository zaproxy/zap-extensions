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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry for MCP resources. Allows resources to be registered and looked up by URI.
 *
 * <p>Thread-safe for concurrent registration and lookup.
 */
public class McpResourceRegistry {

    private final Map<String, McpResource> resources = new ConcurrentHashMap<>();

    /**
     * Registers a resource. If a resource with the same URI already exists, it is replaced.
     *
     * @param resource the resource to register
     * @throws IllegalArgumentException if the resource or its URI is null
     */
    public void registerResource(McpResource resource) {
        if (resource == null) {
            throw new IllegalArgumentException("Resource must not be null");
        }
        String uri = resource.getUri();
        if (uri == null || uri.isBlank()) {
            throw new IllegalArgumentException("Resource URI must not be null or blank");
        }
        resources.put(uri, resource);
    }

    /**
     * Unregisters a resource by URI.
     *
     * @param uri the URI of the resource to unregister
     */
    public void unregisterResource(String uri) {
        resources.remove(uri);
    }

    /**
     * Gets a resource by URI. Performs exact match first, then prefix match (longest matching
     * prefix) for template-style URIs like {@code zap://history/123}.
     *
     * @param uri the resource URI
     * @return the resource, or {@code null} if not registered
     */
    public McpResource getResource(String uri) {
        McpResource exact = resources.get(uri);
        if (exact != null) {
            return exact;
        }
        String longestPrefix = null;
        for (String registeredUri : resources.keySet()) {
            if (uri.startsWith(registeredUri) && uri.length() > registeredUri.length()) {
                if (longestPrefix == null || registeredUri.length() > longestPrefix.length()) {
                    longestPrefix = registeredUri;
                }
            }
        }
        return longestPrefix != null ? resources.get(longestPrefix) : null;
    }

    /**
     * Returns all registered resources.
     *
     * @return an unmodifiable list of resources
     */
    public List<McpResource> getResources() {
        return Collections.unmodifiableList(new ArrayList<>(resources.values()));
    }
}
