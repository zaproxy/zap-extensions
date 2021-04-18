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
package org.zaproxy.addon.exim.har;

import java.io.File;
import net.sf.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.api.ApiAction;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiException.Type;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.utils.ApiUtils;

/** The API for importing URLs from a file. */
public class ImportHarApi extends ApiImplementor {

    private static final Logger LOG = LogManager.getLogger(ImportHarApi.class);
    private static final String PREFIX = "importexport";
    private static final String ACTION_IMPORTHAR = "importhar";
    private static final String PARAM_FILE_PATH = "filePath";

    public ImportHarApi() {
        super();
        this.addApiAction(new ApiAction(ACTION_IMPORTHAR, new String[] {PARAM_FILE_PATH}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiAction(String name, JSONObject params) throws ApiException {
        LOG.debug("handleApiAction {} {}", name, params.toString());

        switch (name) {
            case ACTION_IMPORTHAR:
                HarImportUtil.importHarFile(
                        new File(ApiUtils.getNonEmptyStringParam(params, PARAM_FILE_PATH)));
                return ApiResponseElement.OK;
            default:
                throw new ApiException(Type.BAD_ACTION);
        }
    }
}
