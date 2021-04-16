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

import io.swagger.v3.oas.models.PathItem;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.openapi.network.RequestMethod;

public class OperationHelper {

    private static final Logger log = LogManager.getLogger(OperationHelper.class);

    public List<OperationModel> getAllOperations(PathItem path, String url) {
        List<OperationModel> operations = new LinkedList<OperationModel>();

        if (path.getGet() != null) {
            operations.add(new OperationModel(url, path.getGet(), RequestMethod.GET));
        }
        if (path.getPost() != null) {
            operations.add(new OperationModel(url, path.getPost(), RequestMethod.POST));
        }
        if (path.getPut() != null) {
            operations.add(new OperationModel(url, path.getPut(), RequestMethod.PUT));
        }
        if (path.getHead() != null) {
            operations.add(new OperationModel(url, path.getHead(), RequestMethod.HEAD));
        }
        if (path.getOptions() != null) {
            operations.add(new OperationModel(url, path.getOptions(), RequestMethod.OPTION));
        }
        if (path.getDelete() != null) {
            operations.add(new OperationModel(url, path.getDelete(), RequestMethod.DELETE));
        }
        if (path.getPatch() != null) {
            operations.add(new OperationModel(url, path.getPatch(), RequestMethod.PATCH));
        }
        if (operations.isEmpty()) {
            log.debug("Failed to find any operations for url={} path={}", url, path);
        }

        return operations;
    }
}
