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
package org.zaproxy.zap.extension.soap;

import java.io.File;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;

public class SoapAPI extends ApiImplementor {

    private static final String PREFIX = "soap";
    private static final String ACTION_IMPORT_FILE = "importFile";
    private static final String ACTION_IMPORT_URL = "importUrl";
    private static final String PARAM_URL = "url";
    private static final String PARAM_FILE = "file";
    private final ExtensionImportWSDL extension;

    /** Provided only for API client generator usage. */
    public SoapAPI() {
        this(null);
    }

    public SoapAPI(ExtensionImportWSDL ext) {
        extension = ext;
        this.addApiAction(new ApiAction(ACTION_IMPORT_FILE, new String[] {PARAM_FILE}));
        this.addApiAction(new ApiAction(ACTION_IMPORT_URL, new String[] {PARAM_URL}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        if (ACTION_IMPORT_FILE.equals(name)) {
            File file = new File(params.getString(PARAM_FILE));
            if (!file.exists() || !file.canRead()) {
                throw new ApiException(ApiException.Type.DOES_NOT_EXIST, file.getAbsolutePath());
            }

            extension.fileUrlWSDLImport(file);

            return ApiResponseElement.OK;

        } else if (ACTION_IMPORT_URL.equals(name)) {
            String url = params.getString(PARAM_URL);
            try {
                new URI(url, false);
            } catch (Exception e) {
                throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_URL);
            }

            try {
                extension.extUrlWSDLImport(url);
                return ApiResponseElement.OK;
            } catch (Exception e) {
                throw new ApiException(ApiException.Type.ILLEGAL_PARAMETER, PARAM_URL);
            }

        } else {
            throw new ApiException(ApiException.Type.BAD_ACTION);
        }
    }
}
