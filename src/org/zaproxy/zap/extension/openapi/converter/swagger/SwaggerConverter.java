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
package org.zaproxy.zap.extension.openapi.converter.swagger;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.openapi.converter.Converter;
import org.zaproxy.zap.extension.openapi.generators.Generators;
import org.zaproxy.zap.extension.openapi.network.RequestModel;

import io.swagger.models.Path;
import io.swagger.models.Scheme;
import io.swagger.models.Swagger;
import io.swagger.parser.SwaggerParser;
import io.swagger.parser.util.SwaggerDeserializationResult;

public class SwaggerConverter implements Converter {

    private static Logger LOG = Logger.getLogger(SwaggerConverter.class);
    private String defn;
    private OperationHelper operationHelper;
    private RequestModelConverter requestConverter;
    private Generators generators;
    private final Scheme defaultScheme;

    public SwaggerConverter(String defn) {
        this(null, defn);
    }

    public SwaggerConverter(Scheme defaultScheme, String defn) {
        LOG.debug("Examining defn ");
        this.defaultScheme = defaultScheme;
        generators = new Generators();
        operationHelper = new OperationHelper();
        requestConverter = new RequestModelConverter();
        this.defn = defn;
    }

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
        List<OperationModel> operations = new LinkedList<>();
        Swagger swagger = new SwaggerParser().parse(this.defn);
        if (swagger != null) {
            generators.getModelGenerator().setDefinitions(swagger.getDefinitions());
            List<Scheme> schemes = swagger.getSchemes();
            if (schemes == null || schemes.isEmpty()) {
                if (defaultScheme == null) {
                    throw new SwaggerException("Default scheme required but not provided.");
                }
                addOperations(swagger, defaultScheme, operations);
            } else {
                for (Scheme scheme : swagger.getSchemes()) {
                    addOperations(swagger, scheme, operations);
                }
            }
        } else {
            throw new SwaggerException("Failed to parse swagger defn " + defn);
        }
        return operations;
    }
    
    public List<String> getErrorMessages() {
        List<String> errors = new ArrayList<String> ();
        SwaggerDeserializationResult res = new SwaggerParser().readWithInfo(this.defn);
        if (res != null) {
            errors.addAll(res.getMessages());
        }
        errors.addAll(this.generators.getErrorMessages());
        return errors;
    }

    private void addOperations(Swagger swagger, Scheme scheme, List<OperationModel> operations) {
        switch (scheme) {
        case HTTP:
        case HTTPS:
            for (Map.Entry<String, Path> entry : swagger.getPaths().entrySet()) {
                String url = generators.getPathGenerator().getBasicURL(swagger, scheme, entry.getKey());
                Path path = entry.getValue();
                operations.addAll(operationHelper.getAllOperations(path, url));
            }
            break;
        case WS:
        case WSS:
            // Dont currently support these
            break;
        }
    }

}