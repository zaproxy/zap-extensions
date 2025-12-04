/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.foxhound.taint;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.SessionStructure;
import org.zaproxy.zap.model.StructuralNode;

public class HttpMessageFinder {

    private static final Logger LOGGER = LogManager.getLogger(HttpMessageFinder.class);

    public static HttpMessage findHttpMessage(String url) {
        String[] methods = {"GET", "POST"};
        Model model = Model.getSingleton();

        HistoryReference ref = null;
        HttpMessage msg = null;

        try {
            URI uri = new URI(url, true);
            uri.setFragment("");

            // Try multiple methods as we don't know it from the URL
            for (String method : methods) {
                StructuralNode node = SessionStructure.find(model, uri, method, null);

                if (node != null) {
                    ref = node.getHistoryReference();
                    if (ref != null) {
                        msg = ref.getHttpMessage();
                        break;
                    }
                }
            }

        } catch (URIException | DatabaseException | HttpMalformedHeaderException e) {
            LOGGER.warn("Exception getting HttpMessage for URL: {} ({})", url, e.getMessage());
        }

        return msg;
    }

    public static HttpMessage findHttpMessage(TaintLocation location) {
        return findHttpMessage(location.getFilename());
    }

    public static HttpMessage findHttpMessage(TaintLocationProvider p) {
        return findHttpMessage(p.getLocation());
    }
}
