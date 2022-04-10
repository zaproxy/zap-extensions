/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi.converter.swagger;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.swagger.models.Swagger;
import io.swagger.parser.OpenAPIParser;
import io.swagger.parser.SwaggerCompatConverter;
import io.swagger.parser.SwaggerParser;
import io.swagger.v3.core.util.Json;
import io.swagger.v3.core.util.Yaml;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.servers.ServerVariable;
import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.extensions.SwaggerParserExtension;
import io.swagger.v3.parser.core.models.ParseOptions;
import io.swagger.v3.parser.core.models.SwaggerParseResult;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.regex.Pattern;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.openapi.converter.Converter;
import org.zaproxy.zap.extension.openapi.generators.Generators;
import org.zaproxy.zap.extension.openapi.network.RequestMethod;
import org.zaproxy.zap.extension.openapi.network.RequestModel;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.StructuralNodeModifier;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.utils.Pair;

public class SwaggerConverter implements Converter {

    private static final List<Pair<Function<PathItem, Operation>, RequestMethod>> OPERATIONS;

    static {
        OPERATIONS = new ArrayList<>(7);
        OPERATIONS.add(new Pair<>(PathItem::getGet, RequestMethod.GET));
        OPERATIONS.add(new Pair<>(PathItem::getPost, RequestMethod.POST));
        OPERATIONS.add(new Pair<>(PathItem::getPut, RequestMethod.PUT));
        OPERATIONS.add(new Pair<>(PathItem::getHead, RequestMethod.HEAD));
        OPERATIONS.add(new Pair<>(PathItem::getOptions, RequestMethod.OPTIONS));
        OPERATIONS.add(new Pair<>(PathItem::getDelete, RequestMethod.DELETE));
        OPERATIONS.add(new Pair<>(PathItem::getPatch, RequestMethod.PATCH));
    }

    /** The base key for internationalised messages. */
    private static final String BASE_KEY_I18N = "openapi.swaggerconverter.";

    private static final Logger LOG = LogManager.getLogger(SwaggerConverter.class);
    private static final Pattern PATH_PART_PATTERN = Pattern.compile("\\{.*}");
    private final UriBuilder targetUriBuilder;
    private final UriBuilder definitionUriBuilder;
    private String defn;
    private RequestModelConverter requestConverter;
    private Generators generators;
    private List<String> errors = new ArrayList<>();
    private Set<String> apiUrls;
    private OpenAPI openAPI;

    public SwaggerConverter(String defn, ValueGenerator valGen) {
        this(null, null, defn, valGen);
    }

    /**
     * Constructs a {@code SwaggerConverter} with the given details.
     *
     * <p>The conversion is done/obtained with {@link #getRequestModels()}.
     *
     * @param targetUrl the URL to override the one specified in the definition, might be {@code
     *     null}.
     * @param definitionUrl the URL used to access the definition, might be {@code null} (for
     *     example, if read from file system). The URL is used as default if the scheme or authority
     *     is not specified in the definition or {@code targetUrl}, it's also used to resolve
     *     relative server URLs.
     * @param defn the OpenAPI definition.
     * @param valueGenerator the value generator, might be {@code null} in which case only default
     *     values are used.
     * @throws IllegalArgumentException if the definition is empty or {@code null}.
     * @throws InvalidUrlException if any of the conditions is true:
     *     <ul>
     *       <li>the scheme component of {@code targetUrl} or {@code definitionUrl} is empty when it
     *           shouldn't, for example, {@code ://authority};
     *       <li>the scheme component of {@code targetUrl} or {@code definitionUrl} is not empty
     *           when it should, for example, {@code notscheme//authority};
     *       <li>the {@code targetUrl} or {@code definitionUrl} have an unsupported scheme;
     *       <li>when provided, the {@code definitionUrl} does not have the scheme and authority
     *           components.
     *     </ul>
     */
    public SwaggerConverter(
            String targetUrl, String definitionUrl, String defn, ValueGenerator valueGenerator) {
        if (defn == null || defn.isEmpty()) {
            throw new IllegalArgumentException("The definition must not be null or empty.");
        }

        try {
            this.targetUriBuilder = validateSupportedScheme(UriBuilder.parseLenient(targetUrl));
        } catch (IllegalArgumentException e) {
            throw new InvalidUrlException(
                    targetUrl,
                    Constant.messages.getString(BASE_KEY_I18N + "targeturl.errorsyntax", targetUrl),
                    e);
        }

        try {
            this.definitionUriBuilder = validateSupportedScheme(UriBuilder.parse(definitionUrl));
        } catch (IllegalArgumentException e) {
            throw new InvalidUrlException(
                    definitionUrl,
                    Constant.messages.getString(
                            BASE_KEY_I18N + "definitionurl.errorsyntax", definitionUrl),
                    e);
        }

        if (!this.definitionUriBuilder.isEmpty()
                && (this.definitionUriBuilder.getScheme() == null
                        || this.definitionUriBuilder.getAuthority() == null)) {
            throw new InvalidUrlException(
                    definitionUrl,
                    Constant.messages.getString(
                            BASE_KEY_I18N + "definitionurl.missingcomponents", definitionUrl));
        }

        generators = new Generators(valueGenerator);
        requestConverter = new RequestModelConverter();
        // Remove BOM, if any. Swagger library checks the first char to decide if it should be
        // parsed as JSON or YAML.
        this.defn = defn.replace("\uFEFF", "");
    }

    private static UriBuilder validateSupportedScheme(UriBuilder uriBuilder) {
        if (!hasSupportedScheme(uriBuilder)) {
            throw new InvalidUrlException(
                    uriBuilder.toString(),
                    Constant.messages.getString("openapi.unsupportedscheme", uriBuilder));
        }
        return uriBuilder;
    }

    private static boolean hasSupportedScheme(UriBuilder uriBuilder) {
        String scheme = uriBuilder.getScheme();
        return scheme == null
                || "http".equalsIgnoreCase(scheme)
                || "https".equalsIgnoreCase(scheme);
    }

    @Override
    public List<RequestModel> getRequestModels() throws SwaggerException {
        List<OperationModel> operations = readOpenAPISpec();
        return convertToRequest(operations);
    }

    private List<RequestModel> convertToRequest(List<OperationModel> operations) {
        List<RequestModel> requests = new LinkedList<>();
        for (OperationModel operation : operations) {
            requests.add(requestConverter.convert(operation, generators));
        }
        return requests;
    }

    private List<OperationModel> readOpenAPISpec() throws SwaggerException {
        openAPI = getOpenAPI();
        if (openAPI == null) {
            throw new SwaggerException(
                    Constant.messages.getString(BASE_KEY_I18N + "parse.defn.exception", defn));
        }

        List<OperationModel> operations = new ArrayList<>();
        apiUrls = createApiUrls(openAPI.getServers());
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            PathItem path = entry.getValue();
            Set<String> pathApiUrls = createApiUrls(path.getServers(), apiUrls);

            boolean operationsAdded = false;
            for (Pair<Function<PathItem, Operation>, RequestMethod> operationData : OPERATIONS) {
                Operation operation = operationData.first.apply(path);
                if (operation != null) {
                    operationsAdded = true;
                    for (String url : createApiUrls(operation.getServers(), pathApiUrls)) {
                        operations.add(
                                new OperationModel(
                                        url + entry.getKey(), operation, operationData.second));
                    }
                }
            }

            if (!operationsAdded) {
                LOG.debug("Failed to find any operations for path={}", path);
            }
        }
        return operations;
    }

    private Set<String> createApiUrls(List<Server> servers) throws SwaggerException {
        List<UriBuilder> serverUriBuilders = createUriBuilders(servers, definitionUriBuilder);
        return createApiUrls(serverUriBuilders, targetUriBuilder, definitionUriBuilder);
    }

    private Set<String> createApiUrls(List<Server> servers, Set<String> fallbackApiUrls)
            throws SwaggerException {
        if (servers == null || servers.isEmpty()) {
            return fallbackApiUrls;
        }
        return createApiUrls(servers);
    }

    private OpenAPI getOpenAPI() throws SwaggerException {
        ParseOptions options = new ParseOptions();
        options.setResolve(true);
        options.setResolveFully(true);

        OpenAPI openApiDefn =
                new OpenAPIV3Parser().readContents(this.defn, null, options).getOpenAPI();

        if (openApiDefn == null) {
            // try v2
            Swagger swagger = new SwaggerParser().parse(this.defn);
            if (swagger == null) {
                convertV1ToV2();
            }
            // parse v2
            openApiDefn = parseV2(options);
        }
        return openApiDefn;
    }

    private void convertV1ToV2() throws SwaggerException {
        Swagger swagger;
        // convert older spec to v2
        try {
            // Try the older spec
            // Annoyingly the converter only reads files
            File temp = File.createTempFile("openapi", ".defn");
            BufferedWriter bw = new BufferedWriter(new FileWriter(temp));
            bw.write(this.defn);
            bw.close();

            swagger = new SwaggerCompatConverter().read(temp.getAbsolutePath());

            cleanup(temp.toPath());
            this.defn = Json.mapper().writerWithDefaultPrettyPrinter().writeValueAsString(swagger);

        } catch (IOException e) {
            throw new SwaggerException(
                    Constant.messages.getString(
                            "openapi.swaggerconverter.parse.defn.exception", defn),
                    e);
        }
    }

    private void cleanup(Path path) {
        try {
            Files.delete(path);
        } catch (IOException e) {
            LOG.debug("Failed to delete {}", path);
        }
    }

    private OpenAPI parseV2(ParseOptions options) {
        OpenAPI api;
        try {
            api = new OpenAPIParser().readContents(this.defn, null, options).getOpenAPI();
            // parse again to resolve refs , may be there is a cleaner way
            String string = Yaml.mapper().writerWithDefaultPrettyPrinter().writeValueAsString(api);
            api = new OpenAPIV3Parser().readContents(string, null, options).getOpenAPI();
        } catch (JsonProcessingException e) {
            LOG.warn(e.getMessage());
            api = null;
        }
        return api;
    }

    // Package access for testing.
    static Set<String> createApiUrls(
            List<UriBuilder> serverUriBuilders,
            UriBuilder targetUriBuilder,
            UriBuilder definitionUriBuilder)
            throws SwaggerException {
        if (targetUriBuilder.isEmpty()) {
            Set<String> urls = new TreeSet<>();
            for (UriBuilder serverUrl : serverUriBuilders) {
                try {
                    urls.add(serverUrl.build());
                } catch (IllegalArgumentException e) {
                    String message =
                            "Failed to build/normalise the API URL using Server URL: " + serverUrl;
                    if (!definitionUriBuilder.isEmpty()) {
                        message += " Definition URL: " + definitionUriBuilder;
                    }
                    LOG.warn(message, e);
                }
            }

            if (urls.isEmpty()) {
                throw new SwaggerException(
                        Constant.messages.getString("openapi.swaggerconverter.nourls"));
            }
            return urls;
        }

        UriBuilder finalUriBuilder = targetUriBuilder.copy();

        UriBuilder serverUriBuilder = null;
        if (!serverUriBuilders.isEmpty()) {
            serverUriBuilder = serverUriBuilders.get(0);
            finalUriBuilder.merge(serverUriBuilder);
        }

        if (finalUriBuilder.getScheme() == null || finalUriBuilder.getAuthority() == null) {
            throw new SwaggerException(
                    createExceptionMessageTargetUrl(
                            "missingcomponents",
                            targetUriBuilder,
                            definitionUriBuilder,
                            serverUriBuilder));
        }

        Set<String> urls = new TreeSet<>();
        try {
            urls.add(finalUriBuilder.build());
        } catch (IllegalArgumentException e) {
            throw new SwaggerException(
                    createExceptionMessageTargetUrl(
                            "invalid", targetUriBuilder, definitionUriBuilder, serverUriBuilder),
                    e);
        }
        return urls;
    }

    private static String createExceptionMessageTargetUrl(
            String messageSuffixKey,
            UriBuilder targetUriBuilder,
            UriBuilder definitionUriBuilder,
            UriBuilder serverUriBuilder) {
        String message =
                Constant.messages.getString(
                        BASE_KEY_I18N + "targeturl." + messageSuffixKey, targetUriBuilder);
        if (serverUriBuilder != null && !serverUriBuilder.isEmpty()) {
            message +=
                    "\n"
                            + Constant.messages.getString(
                                    BASE_KEY_I18N + "serverurl", serverUriBuilder);
        }
        if (!definitionUriBuilder.isEmpty()) {
            message +=
                    "\n"
                            + Constant.messages.getString(
                                    BASE_KEY_I18N + "definitionurl", definitionUriBuilder);
        }
        return message;
    }

    // Package access for testing.
    static List<UriBuilder> createUriBuilders(
            List<Server> servers, UriBuilder definitionUriBuilder) {
        List<UriBuilder> urls = new ArrayList<>();
        for (Server server : servers) {
            String url = server.getUrl();
            if (server.getVariables() != null) {
                for (Map.Entry<String, ServerVariable> entry : server.getVariables().entrySet()) {
                    // TODO: Remove the null check in the code below.
                    // The following code is a workaround for a bug in Swagger-Parser where empty
                    // strings were converted to null values.
                    // It was fixed in Swagger-Parser version 2.0.29, but a different bug was
                    // introduced where malformed schemas (e.g. in our unit tests) end up throwing
                    // NPEs instead of returning a list of errors.
                    // See https://github.com/swagger-api/swagger-parser/issues/1685.
                    url =
                            url.replace(
                                    "{" + entry.getKey() + "}",
                                    ObjectUtils.firstNonNull(entry.getValue().getDefault(), ""));
                }
            }
            try {
                UriBuilder uriBuilder = UriBuilder.parse(url);
                if (!hasSupportedScheme(uriBuilder)) {
                    LOG.debug(
                            "Ignoring server URL {} because of unsupported scheme: {}",
                            url,
                            uriBuilder.getScheme());
                    continue;
                }
                if (!uriBuilder.isEmpty()) {
                    uriBuilder.withDefaultPath("");
                }

                urls.add(uriBuilder.merge(definitionUriBuilder));
            } catch (IllegalArgumentException e) {
                LOG.warn("Failed to create server URL from: {}", url, e);
            }
        }
        return urls;
    }

    public List<String> getErrorMessages() {
        ParseOptions options = new ParseOptions();
        options.setResolveFully(true);
        SwaggerParseResult res =
                new OpenAPIV3Parser().readContents(this.defn, new ArrayList<>(), options);
        if (res.getOpenAPI() == null) {
            // try v2
            res = new OpenAPIParser().readContents(this.defn, new ArrayList<>(), options);
        }
        if (res != null && res.getMessages() != null) {
            errors.addAll(res.getMessages());
        }
        errors.addAll(this.generators.getErrorMessages());
        return errors;
    }

    /**
     * File based parser for v2 and v3 specs that bundles external file refs.
     *
     * @param file V2 or V3 OpenAPI File spec, supporting external files via ref
     * @return Populated either with a valid OpenAPI or a list of errors
     */
    public static SwaggerParseResult parse(File file) {
        ParseOptions parseOptions = new ParseOptions();
        parseOptions.setResolve(true);
        parseOptions.setResolveFully(true);

        List<String> errors = new ArrayList<>();
        for (SwaggerParserExtension ex : OpenAPIV3Parser.getExtensions()) {
            SwaggerParseResult swaggerParseResult =
                    ex.readLocation(file.getAbsolutePath(), null, parseOptions);
            if (swaggerParseResult.getOpenAPI() != null) {
                return swaggerParseResult;
            } else {
                errors.addAll(swaggerParseResult.getMessages());
            }
        }

        SwaggerParseResult swaggerParseResult = new SwaggerParseResult();
        swaggerParseResult.setMessages(errors);
        return swaggerParseResult;
    }

    private List<StructuralNodeModifier> getStructuralNodeModifiers() {
        if (openAPI == null) {
            throw new IllegalStateException("The OpenAPI was not yet imported.");
        }

        String targetUrl = apiUrls.stream().findFirst().get();

        Set<String> ddnRegexStrings = new HashSet<>();
        // check for DDN on each key (path) in the spec
        for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
            String key = entry.getKey();
            try {
                List<String> params = getPathParameters(key);
                String ddnPattern = createStructuralNodeRegexString(params, targetUrl, key);
                if (ddnPattern != null) {
                    ddnRegexStrings.add(ddnPattern);
                }
            } catch (Exception e) {
                LOG.error("error evaluating DDN for key: {}", key, e);
            }
        }

        List<StructuralNodeModifier> structuralNodeModifiers = new ArrayList<>();
        int ddnCnt = 0;
        for (String regexString : ddnRegexStrings) {
            try {
                Pattern pattern = Pattern.compile(regexString);
                StructuralNodeModifier structuralNodeModifier =
                        createStructuralNode(pattern, "DDN" + ddnCnt++);
                structuralNodeModifiers.add(structuralNodeModifier);
            } catch (Exception e) {
                LOG.error("error adding structural node", e);
            }
        }

        return structuralNodeModifiers;
    }

    public void setStructuralNodeModifiers(int contextId) {
        if (contextId == -1) {
            return;
        }

        try {
            List<StructuralNodeModifier> structuralNodeModifiers = getStructuralNodeModifiers();
            Context ctx = Model.getSingleton().getSession().getContext(contextId);
            ctx.setDataDrivenNodes(structuralNodeModifiers);
        } catch (Exception e) {
            LOG.error("Error setting data driven nodes from spec for contextId: {}", contextId, e);
            errors.add(e.getMessage());
        }
    }

    private static StructuralNodeModifier createStructuralNode(Pattern pattern, String ddnName) {
        return new StructuralNodeModifier(
                StructuralNodeModifier.Type.DataDrivenNode, pattern, ddnName);
    }

    private static String createStructuralNodeRegexString(
            List<String> params, String finalTargetUrl, String key) {
        if (params.isEmpty()) {
            return null;
        }
        // get last param as the DDN for the key
        String lastParam = params.get(params.size() - 1);

        StringBuilder sb = new StringBuilder();
        if (finalTargetUrl != null) {
            sb.append(finalTargetUrl);
        }

        sb.append('(');
        String pathTill = key.split(lastParam)[0].replace("{", "");
        // replace other params with .+? regex in the first path grouping
        for (String param : params) {
            if (!param.equals(lastParam)) {
                pathTill = pathTill.replace(param, ".+?");
            }
        }
        sb.append(pathTill);
        // add trailing matcher for this DDN
        sb.append(")(.+?)(/.*)");
        return removeBrackets(sb.toString());
    }

    private static List<String> getPathParameters(String key) {
        String[] pathParts = key.split("/");
        List<String> params = new ArrayList<>();
        for (String part : pathParts) {
            if (PATH_PART_PATTERN.matcher(part).matches()) {
                params.add(removeBrackets(part));
            }
        }
        return params;
    }

    private static String removeBrackets(String str) {
        return str.replace("{", "").replace("}", "");
    }
}
