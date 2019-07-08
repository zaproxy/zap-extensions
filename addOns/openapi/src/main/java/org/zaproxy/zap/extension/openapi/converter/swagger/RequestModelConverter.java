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

import io.swagger.models.ArrayModel;
import io.swagger.models.Model;
import io.swagger.models.ModelImpl;
import io.swagger.models.RefModel;
import io.swagger.models.parameters.BodyParameter;
import io.swagger.models.parameters.Parameter;
import io.swagger.models.properties.Property;
import io.swagger.models.properties.PropertyBuilder;
import io.swagger.models.properties.RefProperty;
import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.network.HttpHeaderField;
import org.zaproxy.zap.extension.openapi.generators.Generators;
import org.zaproxy.zap.extension.openapi.generators.HeadersGenerator;
import org.zaproxy.zap.extension.openapi.generators.PathGenerator;
import org.zaproxy.zap.extension.openapi.network.FormData;
import org.zaproxy.zap.extension.openapi.network.RequestModel;

public class RequestModelConverter {

    private OperationModel operationModel;
    private Generators generators;

    public RequestModel convert(OperationModel operationModel, Generators generators) {
        this.generators = generators;
        this.operationModel = operationModel;
        RequestModel requestModel = new RequestModel();
        requestModel.setUrl(this.generatePath());
        requestModel.setBody(this.generateBody());
        requestModel.setMethod(operationModel.getRequestMethod());
        requestModel.setHeaders(this.generateHeaders());
        requestModel.setFormData(this.generateFormData());
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
        String body = null;
        for (Parameter parameter : operationModel.getOperation().getParameters()) {
            if (parameter == null) {
                continue;
            }
            if ("body".equals(parameter.getIn())) {
                Model schema = ((BodyParameter) parameter).getSchema();
                switch (schema.getClass().getSimpleName()) {
                    case "RefModel":
                        body =
                                generators
                                        .getBodyGenerator()
                                        .generate(
                                                ((RefModel) schema).getSimpleRef(),
                                                false,
                                                new ArrayList<String>());
                        break;
                    case "ArrayModel":
                        Property items = ((ArrayModel) schema).getItems();

                        if (items instanceof RefProperty) {
                            body =
                                    generators
                                            .getBodyGenerator()
                                            .generate(
                                                    ((RefProperty) items).getSimpleRef(),
                                                    true,
                                                    new ArrayList<String>());
                        } else {
                            body = generators.getBodyGenerator().generate(items, true);
                        }

                        break;
                    case "ModelImpl":
                        ModelImpl model = ((ModelImpl) schema);
                        Property propertyFromModel =
                                PropertyBuilder.build(model.getType(), model.getFormat(), null);
                        body = generators.getBodyGenerator().generate(propertyFromModel, false);
                        break;
                }
            }
        }
        return body;
    }

    private FormData generateFormData() {
        return generators.getFormGenerator().generate(operationModel);
    }
}
