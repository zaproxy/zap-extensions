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
package org.zaproxy.zap.extension.openapi.automation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.openapi.ExtensionOpenApi;

/**
 * A ProxyListener that automatically detects OpenAPI/Swagger specifications and Swagger UI pages in
 * HTTP responses, and triggers automatic import of discovered specs.
 *
 * <p>This listener monitors all HTTP responses and detects:
 *
 * <ul>
 *   <li>OpenAPI specifications (JSON/YAML with "swagger" or "openapi" keywords)
 *   <li>Swagger UI pages (HTML containing swagger-ui markers)
 *   <li>JavaScript files containing Swagger UI configuration with spec URLs
 * </ul>
 *
 * <p>Detection is purely content-based to avoid false negatives from non-standard URL paths.
 */
public class OpenApiAutoDetectListener implements ProxyListener {

    private static final Logger LOGGER = LogManager.getLogger(OpenApiAutoDetectListener.class);

    /** Listener order - run after other proxy listeners */
    public static final int PROXY_LISTENER_ORDER = 500;

    /** Patterns to detect Swagger UI pages in HTML content */
    private static final List<Pattern> SWAGGER_UI_INDICATORS =
            List.of(
                    Pattern.compile("swagger-ui", Pattern.CASE_INSENSITIVE),
                    Pattern.compile("SwaggerUIBundle", Pattern.CASE_INSENSITIVE),
                    Pattern.compile("swagger-ui-standalone-preset", Pattern.CASE_INSENSITIVE));

    /**
     * Patterns to extract OpenAPI spec URLs from Swagger UI pages and JavaScript files. Matches
     * various configuration formats.
     */
    private static final List<Pattern> SPEC_URL_PATTERNS =
            List.of(
                    // Standard inline config: url: "/path/to/spec.json"
                    Pattern.compile(
                            "(?:url|configUrl)\\s*[=:]\\s*[\"']([^\"']+\\.(?:json|yaml|yml))[\"']",
                            Pattern.CASE_INSENSITIVE),
                    // JSON config: "url":"/swagger/v1/swagger.json"
                    Pattern.compile(
                            "\"url\"\\s*:\\s*\"([^\"]+\\.(?:json|yaml|yml))\"",
                            Pattern.CASE_INSENSITIVE),
                    // JSON config with single quotes
                    Pattern.compile(
                            "'url'\\s*:\\s*'([^']+\\.(?:json|yaml|yml))'",
                            Pattern.CASE_INSENSITIVE),
                    // Any URL in JSON format (for urls array)
                    Pattern.compile("\"url\"\\s*:\\s*\"(/[^\"]+)\"", Pattern.CASE_INSENSITIVE));

    /**
     * Common OpenAPI spec paths to probe when Swagger UI is detected but spec URL cannot be
     * extracted.
     */
    private static final List<String> COMMON_SPEC_PATHS =
            List.of(
                    "swagger.json",
                    "v1/swagger.json",
                    "v2/swagger.json",
                    "v3/swagger.json",
                    "../swagger.json",
                    "../v1/swagger.json",
                    "../v2/swagger.json",
                    "../openapi.json",
                    "../api-docs",
                    "openapi.json",
                    "openapi.yaml",
                    "api-docs");

    private final ExtensionOpenApi extensionOpenApi;
    private final Set<String> importedSpecs;
    private final ExecutorService importExecutor;

    /**
     * Creates a new OpenAPI auto-detection listener.
     *
     * @param extensionOpenApi the OpenAPI extension to use for importing specs
     */
    public OpenApiAutoDetectListener(ExtensionOpenApi extensionOpenApi) {
        this.extensionOpenApi = extensionOpenApi;
        this.importedSpecs = Collections.newSetFromMap(new ConcurrentHashMap<>());
        this.importExecutor = Executors.newSingleThreadExecutor();
    }

    @Override
    public int getArrangeableListenerOrder() {
        return PROXY_LISTENER_ORDER;
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {
        // We only care about responses
        return true;
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {
        try {
            processResponse(msg);
        } catch (Exception e) {
            LOGGER.debug("Error processing response for OpenAPI detection: {}", e.getMessage());
        }
        return true;
    }

    /**
     * Processes an HTTP response to detect and import OpenAPI specifications.
     *
     * @param msg the HTTP message to process
     */
    private void processResponse(HttpMessage msg) {
        String contentType = msg.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE);
        if (contentType == null) {
            return;
        }
        contentType = contentType.toLowerCase(Locale.ROOT);

        String responseBody = msg.getResponseBody().toString();
        if (StringUtils.isBlank(responseBody)) {
            return;
        }

        String url = getUrlString(msg);
        if (url == null) {
            return;
        }

        // 1. Check for direct OpenAPI spec content
        if (isOpenApiSpec(contentType, responseBody)) {
            LOGGER.info("OpenAPI spec detected by content at: {}", url);
            importSpecAsync(url);
            return;
        }

        // 2. Check for Swagger UI pages (HTML)
        if (contentType.contains("html") && isSwaggerUiPage(responseBody)) {
            LOGGER.info("Swagger UI page detected at: {}", url);
            handleSwaggerUiPage(url, responseBody);
            return;
        }

        // 3. Check for JavaScript files with Swagger UI configuration
        if ((contentType.contains("javascript") || contentType.contains("ecmascript"))
                && containsSwaggerUiConfig(responseBody)) {
            LOGGER.info("Swagger UI JavaScript config detected at: {}", url);
            handleSwaggerUiJavaScript(url, responseBody);
        }
    }

    /**
     * Checks if the response content is an OpenAPI specification based on content-type and body.
     */
    private boolean isOpenApiSpec(String contentType, String responseBody) {
        // Check for official OpenAPI content type
        if (contentType.startsWith("application/vnd.oai.openapi")) {
            return true;
        }

        // Check for JSON/YAML content with swagger/openapi keywords
        if (contentType.contains("json") || contentType.contains("yaml")) {
            String bodyStart = StringUtils.left(responseBody, 500).toLowerCase(Locale.ROOT);
            return bodyStart.contains("swagger") || bodyStart.contains("openapi");
        }

        return false;
    }

    /** Checks if the response body indicates a Swagger UI page. */
    private boolean isSwaggerUiPage(String responseBody) {
        for (Pattern pattern : SWAGGER_UI_INDICATORS) {
            if (pattern.matcher(responseBody).find()) {
                return true;
            }
        }
        return false;
    }

    /** Checks if a JavaScript file contains Swagger UI configuration. */
    private boolean containsSwaggerUiConfig(String responseBody) {
        return responseBody.contains("SwaggerUIBundle") || responseBody.contains("swagger-ui");
    }

    /** Extracts OpenAPI spec URLs from Swagger UI content. */
    private List<String> extractSpecUrls(String content) {
        List<String> specUrls = new ArrayList<>();
        for (Pattern pattern : SPEC_URL_PATTERNS) {
            Matcher matcher = pattern.matcher(content);
            while (matcher.find()) {
                String specUrl = matcher.group(1);
                if (!specUrls.contains(specUrl)) {
                    specUrls.add(specUrl);
                }
            }
        }
        return specUrls;
    }

    /** Handles a Swagger UI page by extracting and importing spec URLs. */
    private void handleSwaggerUiPage(String currentUrl, String responseBody) {
        List<String> specUrls = extractSpecUrls(responseBody);

        // If no spec URLs found, try common paths
        if (specUrls.isEmpty()) {
            LOGGER.debug("Could not extract spec URL from Swagger UI, trying common paths");
            specUrls = COMMON_SPEC_PATHS;
        }

        for (String specUrl : specUrls) {
            String resolvedUrl = resolveUrl(currentUrl, specUrl);
            if (resolvedUrl != null) {
                importSpecAsync(resolvedUrl);
            }
        }
    }

    /** Handles a JavaScript file with Swagger UI configuration. */
    private void handleSwaggerUiJavaScript(String currentUrl, String responseBody) {
        List<String> specUrls = extractSpecUrls(responseBody);
        for (String specUrl : specUrls) {
            String resolvedUrl = resolveUrl(currentUrl, specUrl);
            if (resolvedUrl != null) {
                importSpecAsync(resolvedUrl);
            }
        }
    }

    /** Resolves a potentially relative URL against a base URL. */
    private String resolveUrl(String baseUrl, String relativeUrl) {
        try {
            if (relativeUrl.startsWith("http://") || relativeUrl.startsWith("https://")) {
                return relativeUrl;
            }

            URI baseUri = new URI(baseUrl, true);

            if (relativeUrl.startsWith("//")) {
                return baseUri.getScheme() + ":" + relativeUrl;
            }

            if (relativeUrl.startsWith("/")) {
                return baseUri.getScheme()
                        + "://"
                        + baseUri.getHost()
                        + (baseUri.getPort() > 0 ? ":" + baseUri.getPort() : "")
                        + relativeUrl;
            }

            // Relative path
            if (relativeUrl.startsWith("./")) {
                relativeUrl = relativeUrl.substring(2);
            }

            String basePath = baseUri.getPath();
            if (basePath == null) {
                basePath = "/";
            }
            int lastSlash = basePath.lastIndexOf('/');
            String directory = lastSlash >= 0 ? basePath.substring(0, lastSlash + 1) : "/";

            return baseUri.getScheme()
                    + "://"
                    + baseUri.getHost()
                    + (baseUri.getPort() > 0 ? ":" + baseUri.getPort() : "")
                    + directory
                    + relativeUrl;
        } catch (URIException e) {
            LOGGER.debug(
                    "Failed to resolve URL {} against {}: {}",
                    relativeUrl,
                    baseUrl,
                    e.getMessage());
            return null;
        }
    }

    /** Imports an OpenAPI spec asynchronously to avoid blocking the proxy. */
    private void importSpecAsync(String specUrl) {
        // Deduplicate - don't import the same spec twice
        if (!importedSpecs.add(specUrl)) {
            LOGGER.debug("Spec already imported, skipping: {}", specUrl);
            return;
        }

        importExecutor.submit(
                () -> {
                    try {
                        LOGGER.info("Auto-importing OpenAPI spec from: {}", specUrl);
                        URI uri = new URI(specUrl, true);
                        extensionOpenApi.importOpenApiDefinition(uri);
                    } catch (Exception e) {
                        LOGGER.debug(
                                "Failed to import OpenAPI spec from {}: {}",
                                specUrl,
                                e.getMessage());
                        // Remove from imported set so it can be retried
                        importedSpecs.remove(specUrl);
                    }
                });
    }

    /** Gets the URL string from an HTTP message. */
    private String getUrlString(HttpMessage msg) {
        try {
            return msg.getRequestHeader().getURI().toString();
        } catch (Exception e) {
            return null;
        }
    }

    /** Shuts down the import executor. Should be called when the extension is unloaded. */
    public void shutdown() {
        importExecutor.shutdown();
    }

    /** Clears the set of imported specs. Useful for testing or session changes. */
    public void clearImportedSpecs() {
        importedSpecs.clear();
    }
}
