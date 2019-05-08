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

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpHeaderField;
import org.zaproxy.zap.extension.openapi.converter.swagger.OperationModel;

import io.swagger.models.Operation;
import io.swagger.models.parameters.HeaderParameter;
import io.swagger.models.parameters.Parameter;

public class HeadersGenerator {

    private static final String ACCEPT = "Accept";
    private static final String HEADER = "header";
    
    private DataGenerator dataGenerator;
    
    public HeadersGenerator (DataGenerator dataGenerator) {
        this.dataGenerator = dataGenerator;
    }

    public List<HttpHeaderField> generate(OperationModel operationModel) {
        List<HttpHeaderField> headerList = new LinkedList<HttpHeaderField>();
        generateAcceptHeaders(operationModel.getOperation(), headerList);
        generateContentTypeHeaders(operationModel.getOperation(), headerList);
        generateCustomHeader(operationModel.getOperation(), headerList);
        return headerList;
    }

    private void generateCustomHeader(Operation operation, List<HttpHeaderField> headers) {
        if (operation.getParameters() != null) {
            for (Parameter parameter : operation.getParameters()) {
                if (parameter == null) {
                    continue;
                }
                if (HEADER.equals(parameter.getIn())) {
                    String name = parameter.getName();
                    String value = dataGenerator.generate(name, (HeaderParameter) parameter, new ArrayList<String>());
                    HttpHeaderField header = new HttpHeaderField(name, value);
                    headers.add(header);
                }
            }
        }
    }

    private void generateContentTypeHeaders(Operation operation, List<HttpHeaderField> headers) {
        if (operation.getConsumes() != null) {
            for (String type : operation.getConsumes()) {
                if (type.toLowerCase().contains("json")) {
                    // We currently only generate json
                    headers.add(new HttpHeaderField(HttpHeader.CONTENT_TYPE, type));
                    break;
                }
            }
        }
    }

    private void generateAcceptHeaders(Operation operation, List<HttpHeaderField> headers) {
        if (operation.getProduces() != null) {
            // Claim we accept everything
            StringBuilder sb = new StringBuilder();
            for (String type : operation.getProduces()) {
                if (sb.length() > 0) {
                    sb.append(", ");
                }
                sb.append(type);
            }
            headers.add(new HttpHeaderField(ACCEPT, sb.toString()));
        }
    }

}
