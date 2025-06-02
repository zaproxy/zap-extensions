/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.zap.extension.openapi;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.core.scanner.Variant;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.openapi.converter.swagger.OperationModel;

public class VariantOpenApi implements Variant {
    private final ExtensionOpenApi extensionOpenApi;

    public VariantOpenApi() {
        this(Control.getSingleton().getExtensionLoader().getExtension(ExtensionOpenApi.class));
    }

    public VariantOpenApi(ExtensionOpenApi extensionOpenApi) {
        this.extensionOpenApi = extensionOpenApi;
    }

    @Override
    public void setMessage(HttpMessage msg) {}

    @Override
    public List<NameValuePair> getParamList() {
        return Collections.emptyList();
    }

    @Override
    public String setParameter(
            HttpMessage msg, NameValuePair originalPair, String param, String value) {
        return null;
    }

    @Override
    public String setEscapedParameter(
            HttpMessage msg, NameValuePair originalPair, String param, String value) {
        return null;
    }

    @Override
    public List<String> getTreePath(HttpMessage msg) {
        return extensionOpenApi.getTreePath(msg);
    }

    public static class VariantOpenApiChecks {

        public final int contextId;
        public final List<OperationModel> pathsWithNoParams = new ArrayList<>();
        public final Map<OperationModel, Pattern> pathsWithParamsRegex = new HashMap<>();

        public VariantOpenApiChecks(int contextId) {
            this.contextId = contextId;
        }
    }
}
