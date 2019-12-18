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
package org.zaproxy.zap.extension.openapi.generators;

import io.swagger.v3.oas.models.parameters.Parameter;
import org.zaproxy.zap.extension.openapi.converter.swagger.OperationModel;

public class PathGenerator {

    private DataGenerator dataGenerator;

    public PathGenerator(DataGenerator dataGenerator) {
        this.dataGenerator = dataGenerator;
    }

    public String generateFullPath(OperationModel operationModel) {
        String queryString = "?";
        if (operationModel.getOperation().getParameters() != null)
            for (Parameter parameter : operationModel.getOperation().getParameters()) {
                if (parameter == null) {
                    continue;
                }
                String parameterType = parameter.getIn();
                if ("query".equals(parameterType)) {
                    String value = dataGenerator.generate(parameter.getName(), parameter);
                    queryString += parameter.getName() + "=" + value + "&";
                } else if ("path".equals(parameterType)) {
                    String value = dataGenerator.generate(parameter.getName(), parameter);
                    String newPath =
                            operationModel
                                    .getPath()
                                    .replace("{" + parameter.getName() + "}", value);
                    operationModel.setPath(newPath);
                }
            }
        return operationModel.getPath() + queryString.substring(0, queryString.length() - 1);
    }
}
