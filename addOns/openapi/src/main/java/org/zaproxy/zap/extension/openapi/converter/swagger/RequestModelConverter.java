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

import io.swagger.v3.oas.models.examples.Example;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.RequestBody;

import java.io.IOException;
import java.util.List;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeaderField;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.openapi.generators.Generators;
import org.zaproxy.zap.extension.openapi.generators.HeadersGenerator;
import org.zaproxy.zap.extension.openapi.generators.PathGenerator;
import org.zaproxy.zap.extension.openapi.network.RequestModel;
import org.zaproxy.zap.extension.openapi.network.Requestor;

public class RequestModelConverter {

    private static final String APPLICATION_JSON = "application/json";
    private OperationModel operationModel;
    private Generators generators;
    private static final Logger LOG = LogManager.getLogger(RequestModelConverter.class);

    public RequestModel convert(OperationModel operationModel, Generators generators) {
        this.generators = generators;
        this.operationModel = operationModel;
        RequestModel requestModel = new RequestModel();
        requestModel.setUrl(this.generatePath());
        requestModel.setBody(this.generateBody());
        requestModel.setMethod(operationModel.getRequestMethod());
        requestModel.setHeaders(this.generateHeaders());
        return requestModel;
    }

    private List<HttpHeaderField> generateHeaders() {
        HeadersGenerator headersGenerator = new HeadersGenerator(generators.getDataGenerator());
        return headersGenerator.generate(operationModel);
    }

    private String generatePath() {
        PathGenerator pathGenerator = new PathGenerator(generators.getDataGenerator());
        return pathGenerator.generateFullPath(operationModel);
    }

    private String generateBody() {
        RequestBody requestBody = operationModel.getOperation().getRequestBody();
        if (requestBody != null) {
            Content content = requestBody.getContent();
            Schema<?> schema;

            if (content.containsKey(APPLICATION_JSON)) {
                schema = content.get(APPLICATION_JSON).getSchema();
                String exampleBody = extractExampleBody(content, APPLICATION_JSON);
                String generatedBody = exampleBody == null ? generators.getBodyGenerator().generate(schema) : exampleBody;
                return generatedBody;
            }
            if (content.containsKey("application/x-www-form-urlencoded")) {
                schema = content.get("application/x-www-form-urlencoded").getSchema();
                return generators.getBodyGenerator().generateForm(schema);
            }
            if (content.containsKey("application/octet-stream")
                    || content.containsKey("multipart/form-data")) {
                return "";
            }

            if (!content.isEmpty()) {
                schema = content.entrySet().iterator().next().getValue().getSchema();
                return generators.getBodyGenerator().generate(schema);
            }
        }
        return "";
    }

    private String extractExampleBody(Content content, String mediaTypeString) {
        String exampleBody = null;

        if (content.get(mediaTypeString).getExamples() != null
                && !content.get(mediaTypeString).getExamples().isEmpty()
                && content.get(mediaTypeString).getExamples().entrySet().stream().findFirst().get().getValue() != null
        ) {
            Example example = content.get(mediaTypeString).getExamples().entrySet().stream().findFirst().get().getValue();

            if (example.getValue() != null) {
                exampleBody = example.getValue().toString();
            } else if (example.getExternalValue() != null && !example.getExternalValue().isEmpty()) {
                Requestor requestor = new Requestor(HttpSender.MANUAL_REQUEST_INITIATOR);
                URI uri;
                try {
                    uri = new URI(example.getExternalValue(), false);
                    exampleBody = requestor.getResponseBody(uri);
                } catch (IOException e) {
                    LOG.error(e.getMessage(), e);
                }
            }
        } else if (content.get(mediaTypeString).getExample() != null) {
            exampleBody = content.get(mediaTypeString).getExample().toString();
        }
        return exampleBody;
    }
}
