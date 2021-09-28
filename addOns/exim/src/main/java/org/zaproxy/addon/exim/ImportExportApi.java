/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.exim;

import java.io.File;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.exim.har.HarImporter;
import org.zaproxy.addon.exim.urls.UrlsImporter;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiException.Type;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.utils.ApiUtils;

/** The API for importing data from a file. */
public class ImportExportApi extends ApiImplementor {

    private static final Logger LOG = LogManager.getLogger(ImportExportApi.class);
    private static final String PREFIX = "exim";
    private static final String ACTION_IMPORTHAR = "importhar";
    private static final String PARAM_FILE_PATH = "filePath";

    private static final String ACTION_IMPORTURLS = "importurls";

    public ImportExportApi() {
        super();
        this.addApiAction(new ApiAction(ACTION_IMPORTHAR, new String[] {PARAM_FILE_PATH}));
        this.addApiAction(new ApiAction(ACTION_IMPORTURLS, new String[] {PARAM_FILE_PATH}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        LOG.debug("handleApiAction {} {}", name, params);

        boolean success;
        File file;
        switch (name) {
            case ACTION_IMPORTHAR:
                file = new File(ApiUtils.getNonEmptyStringParam(params, PARAM_FILE_PATH));
                success = HarImporter.importHarFile(file);
                return handleFileImportResponse(success, file);
            case ACTION_IMPORTURLS:
                file = new File(ApiUtils.getNonEmptyStringParam(params, PARAM_FILE_PATH));
                success = UrlsImporter.importUrlFile(file);
                return handleFileImportResponse(success, file);
            default:
                throw new ApiException(Type.BAD_ACTION);
        }
    }

    private ApiResponseElement handleFileImportResponse(boolean success, File file)
            throws ApiException {
        if (success) {
            return ApiResponseElement.OK;
        }
        throw new ApiException(Type.BAD_EXTERNAL_DATA, file.getAbsolutePath());
    }
}
