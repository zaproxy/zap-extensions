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
package org.zaproxy.zap.extension.fieldenumeration;

import net.sf.json.JSONObject;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiView;

public class EnumerationAPI extends ApiImplementor {

    private static final String PREFIX = "fieldenumeration";
    private static final String ACTION_SET_FIELD = "enumerateField";
    private static final String VIEW_FIELD = "fieldenumeration";
    private static final String PARAM_FIELD_NAME = "fieldName";
    private static final String PARAM_URL = "url";
    private static final String PARAM_CHARSET = "charset";

    private final ExtensionFieldEnumeration extension;

    public EnumerationAPI(ExtensionFieldEnumeration extension) {
        this.addApiAction(
                new ApiAction(
                        ACTION_SET_FIELD,
                        new String[] {PARAM_URL, PARAM_FIELD_NAME, PARAM_CHARSET}));

        this.addApiView(new ApiView(VIEW_FIELD));

        this.extension = extension;
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {

        if (ACTION_SET_FIELD.equals(name)) {
            extension.enumerateField(
                    params.getString(PARAM_URL),
                    params.getString(PARAM_FIELD_NAME),
                    params.getString(PARAM_CHARSET));
        } else {
            throw new ApiException(ApiException.Type.BAD_ACTION);
        }
        return ApiResponseElement.OK;
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        ApiResponse result = null;

        if (VIEW_FIELD.equals(name)) {
            result = new ApiResponseElement(name, Boolean.toString(extension.isField()));
        } else {
            throw new ApiException(ApiException.Type.BAD_VIEW);
        }
        return result;
    }
}
