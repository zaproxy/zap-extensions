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
import java.util.function.Consumer;
import java.util.stream.Collectors;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;
import org.zaproxy.zap.utils.ApiUtils;

/** The API for manipulating {@link CustomPayload custom payloads}. */
public class CustomPayloadsApi extends ApiImplementor {

    private static final Logger LOGGER = LogManager.getLogger(CustomPayloadsApi.class);
    private static final String PREFIX = "custompayloads";

    private static final String VIEW_CUSTOM_PAYLOADS_CATEGORY_LIST = "customPayloadsCategories";
    private static final String VIEW_CUSTOM_PAYLOADS_LIST = "customPayloads";

    private static final String ACTION_ENABLE = "enableCustomPayloads";
    private static final String ACTION_DISABLE = "disableCustomPayloads";
    private static final String ACTION_REMOVE = "removeCustomPayload";
    private static final String ACTION_ADD = "addCustomPayload";
    private static final String ACTION_ENABLE_PAYLOAD = "enableCustomPayload";
    private static final String ACTION_DISABLE_PAYLOAD = "disableCustomPayload";

    private static final String PARAM_CATEGORY = "category";
    private static final String PARAM_PAYLOAD = "payload";

    private ExtensionCustomPayloads extension;

    /** Provided only for API client generator usage. */
    public CustomPayloadsApi() {
        this(null);
    }

    public CustomPayloadsApi(ExtensionCustomPayloads ext) {
        this.extension = ext;
        this.addApiView(new ApiView(VIEW_CUSTOM_PAYLOADS_CATEGORY_LIST));
        this.addApiView(new ApiView(VIEW_CUSTOM_PAYLOADS_LIST, List.of(), List.of(PARAM_CATEGORY)));

        this.addApiAction(new ApiAction(ACTION_DISABLE, List.of(), List.of(PARAM_CATEGORY)));
        this.addApiAction(new ApiAction(ACTION_ENABLE, List.of(), List.of(PARAM_CATEGORY)));
        this.addApiAction(
                new ApiAction(ACTION_REMOVE, List.of(PARAM_CATEGORY), List.of(PARAM_PAYLOAD)));
        this.addApiAction(
                new ApiAction(ACTION_ADD, List.of(PARAM_CATEGORY), List.of(PARAM_PAYLOAD)));
        this.addApiAction(
                new ApiAction(
                        ACTION_ENABLE_PAYLOAD, List.of(PARAM_CATEGORY), List.of(PARAM_PAYLOAD)));
        this.addApiAction(
                new ApiAction(
                        ACTION_DISABLE_PAYLOAD, List.of(PARAM_CATEGORY), List.of(PARAM_PAYLOAD)));
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
                String category = getValidatedCategory(params.optString(PARAM_CATEGORY));
                getPayloads(category)
                        .forEach(payload -> payloadsList.addItem(payloadToResponse(payload)));
                return payloadsList;

            default:
                throw new ApiException(ApiException.Type.BAD_VIEW);
        }
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        LOGGER.debug("handleApiAction  {} {}", name, params);
        String category;
        String payload;
        int[] count = {0};

        switch (name) {
            case ACTION_DISABLE:
                category = getValidatedCategory(params.optString(PARAM_CATEGORY));
                handlePayloads(getAllPayloads(), x -> x.setEnabled(false), category, count);
                return new ApiResponseElement("disabled", String.valueOf(count[0]));

            case ACTION_ENABLE:
                category = getValidatedCategory(params.optString(PARAM_CATEGORY));
                handlePayloads(getAllPayloads(), x -> x.setEnabled(true), category, count);
                return new ApiResponseElement("enabled", String.valueOf(count[0]));

            case ACTION_REMOVE:
                category = getValidatedCategory(params.getString(PARAM_CATEGORY));
                payload = ApiUtils.getOptionalStringParam(params, PARAM_PAYLOAD);
                List<CustomPayload> payloads = getAllPayloads();
                boolean success = false;
                for (CustomPayload pload : payloads) {
                    if (pload.getCategory().equals(category)
                            && pload.getPayload().equals(payload)) {
                        success = payloads.remove(pload);
                        extension.getParam().setPayloads(payloads);
                        break;
                    }
                }
                return success ? ApiResponseElement.OK : ApiResponseElement.FAIL;

            case ACTION_ADD:
                category = getValidatedCategory(params.getString(PARAM_CATEGORY));
                payload = ApiUtils.getOptionalStringParam(params, PARAM_PAYLOAD);
                List<CustomPayload> ploads = getAllPayloads();
                boolean result = ploads.add(new CustomPayload(category, payload));
                extension.getParam().setPayloads(ploads);
                return result ? ApiResponseElement.OK : ApiResponseElement.FAIL;

            case ACTION_ENABLE_PAYLOAD:
                category = getValidatedCategory(params.getString(PARAM_CATEGORY));
                payload = ApiUtils.getOptionalStringParam(params, PARAM_PAYLOAD);
                handlePayload(category, payload, x -> x.setEnabled(true));
                return ApiResponseElement.OK;

            case ACTION_DISABLE_PAYLOAD:
                category = getValidatedCategory(params.getString(PARAM_CATEGORY));
                payload = ApiUtils.getOptionalStringParam(params, PARAM_PAYLOAD);
                handlePayload(category, payload, x -> x.setEnabled(false));
                return ApiResponseElement.OK;

            default:
                throw new ApiException(ApiException.Type.BAD_ACTION);
        }
    }

    private void handlePayloads(
            List<CustomPayload> payloads,
            Consumer<CustomPayload> handler,
            String category,
            int[] count) {
        payloads.forEach(
                payload -> {
                    if (category.isEmpty() || payload.getCategory().equals(category)) {
                        handler.accept(payload);
                        count[0]++;
                    }
                });
        extension.getParam().setPayloads(payloads);
    }

    private void handlePayload(String category, String payload, Consumer<CustomPayload> handler)
            throws ApiException {
        List<CustomPayload> payloads = extension.getParam().getPayloads();
        boolean[] success = {false};
        payloads.forEach(
                x -> {
                    if (x.getCategory().equals(category) && x.getPayload().equals(payload)) {
                        handler.accept(x);
                        success[0] = true;
                    }
                });
        if (!success[0]) {
            throw new ApiException(
                    ApiException.Type.ILLEGAL_PARAMETER,
                    "Could not find payload matching: Category: "
                            + category
                            + " Payload: "
                            + payload);
        }
        extension.getParam().setPayloads(payloads);
    }

    private List<CustomPayload> getAllPayloads() {
        return getPayloads("");
    }

    private List<CustomPayload> getPayloads(String category) {
        return category.isBlank()
                ? extension.getParam().getPayloads()
                : extension.getParam().getPayloads().stream()
                        .filter(payload -> payload.getCategory().equalsIgnoreCase(category))
                        .collect(Collectors.toList());
    }

    private String getValidatedCategory(String category) throws ApiException {
        if (!category.isEmpty() && !isValidCategory(category)) {
            throw new ApiException(
                    ApiException.Type.ILLEGAL_PARAMETER, "Could not find category: " + category);
        }
        return category;
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
