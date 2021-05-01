/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.wappalyzer;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import net.sf.json.JSONObject;
import org.zaproxy.zap.extension.api.ApiException;
import org.zaproxy.zap.extension.api.ApiImplementor;
import org.zaproxy.zap.extension.api.ApiResponse;
import org.zaproxy.zap.extension.api.ApiResponseElement;
import org.zaproxy.zap.extension.api.ApiResponseList;
import org.zaproxy.zap.extension.api.ApiResponseSet;
import org.zaproxy.zap.extension.api.ApiView;

public class WappalyzerAPI extends ApiImplementor {

    public static final String PREFIX = "wappalyzer";

    private static final String VIEW_LIST_SITES = "listSites";
    private static final String VIEW_LIST_ALL = "listAll";
    private static final String VIEW_LIST_SITE = "listSite";

    private static final String PARAM_SITE = "site";

    private ExtensionWappalyzer extension = null;

    /** Provided only for API client generator usage. */
    public WappalyzerAPI() {
        this(null);
    }

    public WappalyzerAPI(ExtensionWappalyzer ext) {
        this.extension = ext;
        this.addApiView(new ApiView(VIEW_LIST_SITES));
        this.addApiView(new ApiView(VIEW_LIST_ALL));
        this.addApiView(new ApiView(VIEW_LIST_SITE, new String[] {PARAM_SITE}));
    }

    @Override
    public String getPrefix() {
        return PREFIX;
    }

    @Override
    public ApiResponse handleApiView(String name, JSONObject params) throws ApiException {
        ApiResponse result = null;
        if (VIEW_LIST_SITES.equals(name)) {
            result = sitesToList(name, extension.getSites());
        } else if (VIEW_LIST_ALL.equals(name)) {
            ApiResponseList sitesList = new ApiResponseList(name);
            for (String site : extension.getSites()) {
                sitesList.addItem(getAppListForSite(site));
            }
            result = sitesList;
        } else if (VIEW_LIST_SITE.equals(name)) {
            String site = getParam(params, PARAM_SITE, "");
            validateSite(site);
            result = getAppListForSite(site);
        }
        return result;
    }

    private void validateSite(String site) throws ApiException {
        if (!extension.getSites().contains(site)) {
            throw new ApiException(ApiException.Type.DOES_NOT_EXIST, PARAM_SITE);
        }
    }

    private ApiResponseList getAppListForSite(String site) {
        ApiResponseList resultList = new ApiResponseList(site);
        TechTableModel ttm = extension.getTechModelForSite(site);
        for (int i = 0; i < ttm.getRowCount(); i++) {
            Map<String, String> map = new HashMap<>();
            map.put("name", ((Application) ttm.getValueAt(i, 0)).toString());
            map.put("description", ttm.getApp(i).getDescription());
            map.put("version", (String) ttm.getValueAt(i, 1));
            map.put("category", (String) ttm.getValueAt(i, 2));
            map.put("website", (String) ttm.getValueAt(i, 3));
            map.put("implies", (String) ttm.getValueAt(i, 4));
            map.put("cpe", (String) ttm.getValueAt(i, 5));
            resultList.addItem(new ApiResponseSet<String>("app", map));
        }
        return resultList;
    }

    private ApiResponseList sitesToList(String name, Set<String> sites) {
        ApiResponseList resultList = new ApiResponseList(name);
        sites.forEach((site) -> resultList.addItem(new ApiResponseElement("site", site)));
        return resultList;
    }
}
