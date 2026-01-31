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

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import graphql.introspection.IntrospectionQueryBuilder;
import graphql.introspection.IntrospectionResultToSchema;
import graphql.language.Document;
import graphql.schema.GraphQLSchema;
import graphql.schema.idl.SchemaParser;
import graphql.schema.idl.SchemaPrinter;
import graphql.schema.idl.UnExecutableSchemaGenerator;
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
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.utils.Stats;

public class GraphQlParser {

    private static final Logger LOGGER = LogManager.getLogger(GraphQlParser.class);
    private static final String THREAD_PREFIX = "ZAP-GraphQL-Parser";
    private static final String INTROSPECTION_QUERY =
            IntrospectionQueryBuilder.build(
                    IntrospectionQueryBuilder.Options.defaultOptions()
                            .descriptions(false)
                            .directiveIsRepeatable(false)
                            .inputValueDeprecation(false)
                            .isOneOf(false));
    private static AtomicInteger threadId = new AtomicInteger();
    private static final String INTROSPECTION_ALERT_REF = ExtensionGraphQl.TOOL_ALERT_ID + "-1";
    private static final Map<String, String> INTROSPECTION_ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final URI endpointUrl;
    private final GraphQlQueryMessageBuilder queryMsgBuilder;
    private final Requestor requestor;
    private final ExtensionGraphQl extensionGraphQl;
    private final GraphQlParam param;
    private boolean syncParse;

    // For Unit Tests
    protected GraphQlParser(String endpointUrlStr) throws URIException {
        extensionGraphQl = new ExtensionGraphQl();
        param = extensionGraphQl.getParam();
        endpointUrl = UrlBuilder.build(endpointUrlStr);
        queryMsgBuilder = new GraphQlQueryMessageBuilder(endpointUrl);
        requestor = new Requestor(queryMsgBuilder, HttpSender.MANUAL_REQUEST_INITIATOR);
    }

    public GraphQlParser(String endpointUrlStr, int initiator, boolean syncParse)
            throws URIException {
        this(UrlBuilder.build(endpointUrlStr), initiator, syncParse);
    }

    public GraphQlParser(URI endpointUrl, int initiator, boolean syncParse) {
        this.endpointUrl = endpointUrl;
        queryMsgBuilder = new GraphQlQueryMessageBuilder(endpointUrl);
        requestor = new Requestor(queryMsgBuilder, initiator);
        extensionGraphQl =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionGraphQl.class);
        param = extensionGraphQl.getParam();
        this.syncParse = syncParse;
    }

    public void introspect() throws IOException {
        introspect(false);
    }

    public void introspect(boolean raiseAlert) throws IOException {
        HttpMessage importMessage =
                requestor.sendQuery(
                        INTROSPECTION_QUERY, GraphQlParam.RequestMethodOption.POST_JSON);
        if (importMessage == null) {
            throw new IOException(Constant.messages.getString("graphql.error.introspection"));
        }
        String schemaSdl =
                getSchemaFromIntrospectionResponse(importMessage.getResponseBody().toString());
        if (raiseAlert) {
            raiseIntrospectionAlert(importMessage);
        }
        parse(schemaSdl);
        Stats.incCounter(GraphQlStats.INTROSPECTION_URL_IMPORTED);
    }

    public void importUrl(String schemaUrlStr) throws IOException {
        importUrl(UrlBuilder.build(schemaUrlStr));
    }

    public void importUrl(URI schemaUrl) throws IOException {
        HttpMessage importMessage = new HttpMessage(schemaUrl);
        requestor.send(importMessage);
        parse(importMessage.getResponseBody().toString());
        Stats.incCounter(GraphQlStats.SCHEMA_URL_IMPORTED);
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
        String schema = FileUtils.readFileToString(file, StandardCharsets.UTF_8);
        if (schema.stripLeading().startsWith("{")) {
            schema = getSchemaFromIntrospectionResponse(schema);
        }
        parse(schema);
        Stats.incCounter(GraphQlStats.SCHEMA_FILE_IMPORTED);
    }

    private static String getSchemaFromIntrospectionResponse(String response) throws IOException {
        try {
            Map<String, Object> result = MAPPER.readValue(response, new TypeReference<>() {});
            if (result == null) {
                throw new IOException(Constant.messages.getString("graphql.error.emptySchema"));
            }
            Map<String, Object> data =
                    MAPPER.convertValue(result.get("data"), new TypeReference<>() {});
            if (data == null) {
                throw new IOException(Constant.messages.getString("graphql.error.nullData"));
            }
            Document schema = new IntrospectionResultToSchema().createSchemaDefinition(data);
            return new SchemaPrinter().print(schema);
        } catch (JacksonException e) {
            throw new IOException(Constant.messages.getString("graphql.error.invalidJson"));
        }
    }

    public void parse(String sdl) {
        GraphQLSchema schema =
                UnExecutableSchemaGenerator.makeUnExecutableSchema(new SchemaParser().parse(sdl));
        var generator =
                new GraphQlGenerator(
                        extensionGraphQl.getValueGenerator(), schema, requestor, param);
        if (syncParse) {
            fingerprint();
            detectCycles(schema, generator);
            if (param.getQueryGenEnabled()) {
                generate(generator);
            }
            return;
        }
        ParserThread t =
                new ParserThread(THREAD_PREFIX + threadId.incrementAndGet()) {
                    @Override
                    public void run() {
                        fingerprint();
                        detectCycles(schema, generator);
                        if (param.getQueryGenEnabled()) {
                            generate(generator);
                        }
                    }
                };
        extensionGraphQl.addParserThread(t);
        t.startParser();
    }

    private void fingerprint() {
        new GraphQlFingerprinter(endpointUrl, requestor).fingerprint();
    }

    private void detectCycles(GraphQLSchema schema, GraphQlGenerator generator) {
        new GraphQlCycleDetector(schema, generator, queryMsgBuilder, param).detectCycles();
    }

    private void generate(GraphQlGenerator generator) {
        try {
            generator.checkServiceMethods();
            generator.generateAndSend();
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    static Alert.Builder createIntrospectionAlert() {
        return Alert.builder()
                .setPluginId(ExtensionGraphQl.TOOL_ALERT_ID)
                .setAlertRef(INTROSPECTION_ALERT_REF)
                .setName(Constant.messages.getString("graphql.introspection.alert.name"))
                .setDescription(Constant.messages.getString("graphql.introspection.alert.desc"))
                .setReference(Constant.messages.getString("graphql.introspection.alert.ref"))
                .setSolution(Constant.messages.getString("graphql.introspection.alert.soln"))
                .setConfidence(Alert.CONFIDENCE_HIGH)
                .setRisk(Alert.RISK_INFO)
                .setCweId(16)
                .setWascId(15)
                .setSource(Alert.Source.TOOL)
                .setTags(INTROSPECTION_ALERT_TAGS);
    }

    private void raiseIntrospectionAlert(HttpMessage msg) {
        var extAlert =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionAlert.class);
        if (extAlert == null) {
            return;
        }
        Alert alert =
                createIntrospectionAlert()
                        .setHistoryRef(msg.getHistoryRef())
                        .setMessage(msg)
                        .build();
        extAlert.alertFound(alert, msg.getHistoryRef());
    }

    public void addRequesterListener(RequesterListener listener) {
        requestor.addListener(listener);
    }
}
