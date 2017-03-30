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
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.openapi.generators;

import org.zaproxy.zap.extension.openapi.converter.swagger.OperationModel;
import org.zaproxy.zap.extension.openapi.network.FormData;
import org.zaproxy.zap.extension.openapi.network.FormDataItem;

import io.swagger.models.parameters.AbstractSerializableParameter;
import io.swagger.models.parameters.FormParameter;
import io.swagger.models.parameters.Parameter;

public class FormGenerator {

    private DataGenerator dataGenerator;

    public FormGenerator (DataGenerator dataGenerator) {
        this.dataGenerator = dataGenerator;
    }

    public FormData generate(OperationModel operationModel) {
        FormData formData = new FormData(operationModel.getOperation().getConsumes());
        for (Parameter parameter : operationModel.getOperation().getParameters()) {
            String parameterType = parameter.getIn();
            if (parameterType.equals("formData")) {
                String type = ((AbstractSerializableParameter<?>) parameter).getType();
                FormDataItem item = new FormDataItem();
                item.setIsFile(type != null && type.equals("file"));
                item.setValue(dataGenerator.generate((FormParameter) parameter));
                formData.addFormItem(parameter.getName(), item);
            }
        }
        return formData;
    }
}
