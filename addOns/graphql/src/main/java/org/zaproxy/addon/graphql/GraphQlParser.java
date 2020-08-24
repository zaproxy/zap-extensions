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
import graphql.introspection.IntrospectionQuery;
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
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.graphql.GraphQlGenerator.RequestType;

public class GraphQlParser {

    private static final Logger LOG = Logger.getLogger(GraphQlParser.class);
    private static final String THREAD_PREFIX = "ZAP-GraphQL-Parser";
    private static AtomicInteger threadId = new AtomicInteger();

    private final Requestor requestor;
    private final GraphQlParam param =
            Control.getSingleton()
                    .getExtensionLoader()
                    .getExtension(ExtensionGraphQl.class)
                    .getParam();

    public GraphQlParser(String endpointUrlStr, int initiator) throws URIException {
        this(UrlBuilder.build(endpointUrlStr), initiator);
    }

    public GraphQlParser(URI endpointUrl, int initiator) {
        requestor = new Requestor(endpointUrl, initiator);
    }

    public void introspect() throws IOException {
        HttpMessage importMessage =
                requestor.sendQuery(
                        IntrospectionQuery.INTROSPECTION_QUERY,
                        GraphQlParam.RequestMethodOption.POST_JSON);

        try {
            Map<String, Object> result =
                    new Gson()
                            .fromJson(
                                    importMessage.getResponseBody().toString(),
                                    new TypeToken<Map<String, Object>>() {}.getType());
            @SuppressWarnings("unchecked")
            Document schema =
                    new IntrospectionResultToSchema()
                            .createSchemaDefinition((Map<String, Object>) result.get("data"));
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
        if (MessageValidator.validate(importMessage) == MessageValidator.Result.VALID_SCHEMA) {
            requestor.send(importMessage);
            parse(importMessage.getResponseBody().toString());
        } else {
            throw new IOException("Invalid Schema at " + schemaUrl);
        }
    }

    public void importFile(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new FileNotFoundException(
                    Constant.messages.getString("graphql.error.filenotfound"));
        }
        if (!file.canRead() || !file.isFile()) {
            throw new IOException(Constant.messages.getString("graphql.error.importfile"));
        }
        String schemaSdl = FileUtils.readFileToString(file, StandardCharsets.UTF_8);
        parse(schemaSdl);
    }

    public void parse(String schema) {
        Thread t =
                new Thread(THREAD_PREFIX + threadId.incrementAndGet()) {
                    @Override
                    public void run() {
                        try {
                            GraphQlGenerator generator =
                                    new GraphQlGenerator(schema, requestor, param);
                            generator.checkServiceMethods();
                            switch (param.getQuerySplitType()) {
                                case DO_NOT_SPLIT:
                                    generator.sendFull(RequestType.QUERY);
                                    generator.sendFull(RequestType.MUTATION);
                                    generator.sendFull(RequestType.SUBSCRIPTION);
                                    break;
                                case ROOT_FIELD:
                                    generator.sendByField(RequestType.QUERY);
                                    generator.sendByField(RequestType.MUTATION);
                                    generator.sendByField(RequestType.SUBSCRIPTION);
                                    break;
                                case LEAF:
                                default:
                                    generator.sendByLeaf(RequestType.QUERY);
                                    generator.sendByLeaf(RequestType.MUTATION);
                                    generator.sendByLeaf(RequestType.SUBSCRIPTION);
                                    break;
                            }
                        } catch (Exception e) {
                            LOG.error(e.getMessage());
                        }
                    }
                };
        t.start();
    }

    public void addRequesterListener(RequesterListener listener) {
        requestor.addListener(listener);
    }
}
