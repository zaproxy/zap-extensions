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

import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.Encoding;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.RequestBody;
import java.util.List;
import java.util.Map;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpHeaderField;
import org.zaproxy.zap.extension.openapi.generators.Generators;
import org.zaproxy.zap.extension.openapi.generators.HeadersGenerator;
import org.zaproxy.zap.extension.openapi.generators.PathGenerator;
import org.zaproxy.zap.extension.openapi.network.RequestModel;

public class RequestModelConverter {

    private static final String CONTENT_APPLICATION_XML = "application/xml";
    private OperationModel operationModel;
    private Generators generators;

    public RequestModel convert(OperationModel operationModel, Generators generators) {
        this.generators = generators;
        this.operationModel = operationModel;
        RequestModel requestModel = new RequestModel();
        requestModel.setUrl(this.generatePath());
        requestModel.setBody(this.generateBody());
        requestModel.setMethod(operationModel.getRequestMethod());
        requestModel.setHeaders(this.generateHeaders(requestModel.getBody()));
        return requestModel;
    }

    private List<HttpHeaderField> generateHeaders(String requestBody) {
        HeadersGenerator headersGenerator = new HeadersGenerator(generators.getDataGenerator());
        return headersGenerator.generate(operationModel, requestBody);
    }

    private String generatePath() {
        PathGenerator pathGenerator = new PathGenerator(generators.getDataGenerator());
        return pathGenerator.generateFullPath(operationModel);
    }

    private String generateBody() {
        Operation operation = operationModel.getOperation();
        RequestBody requestBody = operation.getRequestBody();
        if (requestBody != null) {
            Content content = requestBody.getContent();
            Schema<?> schema;

            if (content.containsKey("application/json")) {
                return generators.getBodyGenerator().generate(content.get("application/json"));
            }
            if (content.containsKey("application/octet-stream")) {
                schema = content.get("application/octet-stream").getSchema();
                return generators.getBodyGenerator().generate(schema);
            }
            if (content.containsKey("application/x-www-form-urlencoded")) {
                schema = content.get("application/x-www-form-urlencoded").getSchema();
                return generators.getBodyGenerator().generateForm(schema);
            }
            String formdataType = "multipart/form-data";
            if (content.containsKey(formdataType)) {
                schema = content.get(formdataType).getSchema();
                Map<String, Encoding> encoding = content.get(formdataType).getEncoding();
                return generators.getBodyGenerator().generateMultiPart(schema, encoding);
            }

            if (content.containsKey(CONTENT_APPLICATION_XML)) {
                generators.addErrorMessage(
                        Constant.messages.getString(
                                "openapi.unsupportedcontent",
                                operation.getOperationId(),
                                CONTENT_APPLICATION_XML));
                return "";
            }

            if (!content.isEmpty()) {
                schema = content.entrySet().iterator().next().getValue().getSchema();
                return generators.getBodyGenerator().generate(schema);
            }
        }
        return "";
    }
}
