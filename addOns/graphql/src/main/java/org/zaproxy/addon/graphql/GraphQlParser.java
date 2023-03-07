/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.graphql;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import graphql.introspection.IntrospectionQueryBuilder;
import graphql.introspection.IntrospectionResultToSchema;
import graphql.language.Document;
import graphql.schema.idl.SchemaPrinter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.io.FileUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;

public class GraphQlParser {

    private static final Logger LOGGER = LogManager.getLogger(GraphQlParser.class);
    private static final String THREAD_PREFIX = "ZAP-GraphQL-Parser";
    private static final String INTROSPECTION_QUERY =
            IntrospectionQueryBuilder.build(
                    IntrospectionQueryBuilder.Options.defaultOptions()
                            .descriptions(false)
                            .directiveIsRepeatable(false)
                            .inputValueDeprecation(false));
    private static AtomicInteger threadId = new AtomicInteger();

    private final Requestor requestor;
    private final ExtensionGraphQl extensionGraphQl;
    private final GraphQlParam param;
    private boolean syncParse;

    // For Unit Tests
    protected GraphQlParser(String endpointUrlStr) throws URIException {
        extensionGraphQl = new ExtensionGraphQl();
        param = extensionGraphQl.getParam();
        requestor =
                new Requestor(
                        UrlBuilder.build(endpointUrlStr), HttpSender.MANUAL_REQUEST_INITIATOR);
    }

    public GraphQlParser(String endpointUrlStr, int initiator, boolean syncParse)
            throws URIException {
        this(UrlBuilder.build(endpointUrlStr), initiator, syncParse);
    }

    public GraphQlParser(URI endpointUrl, int initiator, boolean syncParse) {
        requestor = new Requestor(endpointUrl, initiator);
        extensionGraphQl =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionGraphQl.class);
        param = extensionGraphQl.getParam();
        this.syncParse = syncParse;
    }

    public void introspect() throws IOException {
        HttpMessage importMessage =
                requestor.sendQuery(
                        INTROSPECTION_QUERY, GraphQlParam.RequestMethodOption.POST_JSON);
        if (importMessage == null) {
            throw new IOException("Could not obtain schema via Introspection.");
        }
        try {
            Map<String, Object> result =
                    new Gson()
                            .fromJson(
                                    importMessage.getResponseBody().toString(),
                                    new TypeToken<Map<String, Object>>() {}.getType());
            if (result == null) {
                throw new IOException("The response was empty.");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> data = (Map<String, Object>) result.get("data");
            if (data == null) {
                throw new IOException(
                        "The \"data\" object in the introspection response was null.");
            }
            Document schema = new IntrospectionResultToSchema().createSchemaDefinition(data);
            String schemaSdl = new SchemaPrinter().print(schema);
            parse(schemaSdl);
        } catch (JsonSyntaxException e) {
            throw new IOException("The response was not valid JSON.");
        }
    }

    public void importUrl(String schemaUrlStr) throws IOException {
        importUrl(UrlBuilder.build(schemaUrlStr));
    }

    public void importUrl(URI schemaUrl) throws IOException {
        HttpMessage importMessage = new HttpMessage(schemaUrl);
        requestor.send(importMessage);
        if (MessageValidator.validate(importMessage) == MessageValidator.Result.VALID_SCHEMA) {
            parse(importMessage.getResponseBody().toString());
        } else {
            throw new IOException("Invalid Schema at " + schemaUrl);
        }
    }

    public void importFile(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new FileNotFoundException(
                    Constant.messages.getString("graphql.error.filenotfound", filePath));
        }
        if (!file.canRead() || !file.isFile()) {
            throw new IOException(Constant.messages.getString("graphql.error.importfile"));
        }
        String schemaSdl = FileUtils.readFileToString(file, StandardCharsets.UTF_8);
        parse(schemaSdl);
    }

    public void parse(String schema) {
        if (syncParse) {
            generate(schema);
            return;
        }
        ParserThread t =
                new ParserThread(THREAD_PREFIX + threadId.incrementAndGet()) {
                    @Override
                    public void run() {
                        generate(schema);
                    }
                };
        extensionGraphQl.addParserThread(t);
        t.startParser();
    }

    private void generate(String schema) {
        try {
            GraphQlGenerator generator =
                    new GraphQlGenerator(
                            extensionGraphQl.getValueGenerator(), schema, requestor, param);
            generator.checkServiceMethods();
            generator.generateAndSend();
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    public void addRequesterListener(RequesterListener listener) {
        requestor.addListener(listener);
    }
}
