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
package org.zaproxy.zap.extension.custompayloads;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;

/** The API for manipulating {@link CustomPayload custom payloads}. */
public class CustomPayloadsApi extends ApiImplementor {

    private static final Logger LOGGER = LogManager.getLogger(CustomPayloadsApi.class);
    private static final String PREFIX = "custompayloads";
    private static final String VIEW_CUSTOM_PAYLOADS_CATEGORY_LIST = "customPayloadsCategories";
    private static final String VIEW_CUSTOM_PAYLOADS_LIST = "customPayloads";

    private static final String PARAM_CATEGORY = "category";
    private ExtensionCustomPayloads extension;

    /** Provided only for API client generator usage. */
    public CustomPayloadsApi() {
        this(null);
    }

    public CustomPayloadsApi(ExtensionCustomPayloads ext) {
        this.extension = ext;
        this.addApiView(new ApiView(VIEW_CUSTOM_PAYLOADS_CATEGORY_LIST));
        this.addApiView(new ApiView(VIEW_CUSTOM_PAYLOADS_LIST, List.of(), List.of(PARAM_CATEGORY)));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        LOGGER.debug("handleApiView {} {}", name, params);

        switch (name) {
            case VIEW_CUSTOM_PAYLOADS_CATEGORY_LIST:
                ApiResponseList listResponse = new ApiResponseList(name);

                for (String cat : extension.getParam().getCategoriesNames()) {
                    listResponse.addItem(new ApiResponseElement("category", cat));
                }
                return listResponse;

            case VIEW_CUSTOM_PAYLOADS_LIST:
                ApiResponseList payloadsList = new ApiResponseList(name);
                String category = params.optString(PARAM_CATEGORY);
                getPayloads(category)
                        .forEach(payload -> payloadsList.addItem(payloadToResponse(payload)));
                return payloadsList;

            default:
                throw new ApiException(ApiException.Type.BAD_VIEW);
        }
    }

    private List<CustomPayload> getPayloads(String category) throws ApiException {
        if (!category.isBlank() && !isValidCategory(category)) {
            throw new ApiException(
                    ApiException.Type.DOES_NOT_EXIST, "Could not find category: " + category);
        }

        return category.isBlank()
                ? extension.getParam().getPayloads()
                : extension.getParam().getPayloads().stream()
                        .filter(payload -> payload.getCategory().equalsIgnoreCase(category))
                        .collect(Collectors.toList());
    }

    private boolean isValidCategory(String category) {
        return extension.getParam().getCategoriesNames().stream()
                .anyMatch(x -> x.equalsIgnoreCase(category));
    }

    private static ApiResponse payloadToResponse(CustomPayload payload) {
        Map<String, Object> map = new HashMap<>();
        map.put("category", payload.getCategory());
        map.put("payload", payload.getPayload());
        map.put("enabled", payload.isEnabled());
        return new ApiResponseSet<>("custompayload", map);
    }
}
