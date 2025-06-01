/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.dev;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.dev.gen.openapi.ZapApiDefinition;
import org.zaproxy.zap.extension.api.API;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiOther;

public class DevApi extends ApiImplementor {

    private static final Logger LOGGER = LogManager.getLogger(DevApi.class);

    private static final String PREFIX = "dev";

    private static final String OTHER_OPENAPI = "openapi";

    public DevApi() {
        this.addApiOthers(new ApiOther(OTHER_OPENAPI, false));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public HttpMessage handleApiOther(HttpMessage msg, String name, JSONObject params)
            throws ApiException {
        switch (name) {
            case OTHER_OPENAPI:
                var definition = new ZapApiDefinition(API.getInstance().getImplementors().values());

                try {
                    String result =
                            new ObjectMapper(new YAMLFactory()).writeValueAsString(definition);
                    msg.setResponseBody(result);
                    msg.setResponseHeader(
                            API.getDefaultResponseHeader(
                                            "application/yaml", msg.getResponseBody().length())
                                    + "Content-Disposition: attachment; filename=\"openapi.yaml\"\r\n");
                } catch (Exception e) {
                    LOGGER.warn(e.getMessage(), e);
                }
                return msg;

            default:
                return super.handleApiOther(msg, name, params);
        }
    }
}
