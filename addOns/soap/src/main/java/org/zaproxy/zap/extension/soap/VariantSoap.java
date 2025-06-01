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
package org.zaproxy.zap.extension.soap;

import java.util.ArrayList;
import java.util.List;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.core.scanner.Variant;
import org.parosproxy.paros.network.HttpMessage;

public class VariantSoap implements Variant {

    private static final String[] EMPTY_ARRAY = {};

    @Override
    public void setMessage(HttpMessage msg) {}

    @Override
    public List<NameValuePair> getParamList() {
        return List.of();
    }

    @Override
    public String setEscapedParameter(
            HttpMessage msg, NameValuePair originalPair, String param, String value) {
        return setParameter(msg, originalPair, param, value);
    }

    @Override
    public String setParameter(
            HttpMessage msg, NameValuePair originalPair, String param, String value) {
        return null;
    }

    @Override
    public List<String> getTreePath(HttpMessage msg) throws URIException {
        String nodeName = SitesTreeHelper.getNodeName(msg);
        if (nodeName.isEmpty()) {
            // Not a SOAP message.
            return null;
        }

        URI uri = msg.getRequestHeader().getURI();
        String[] path = uri.getRawPath() != null ? uri.getPath().split("/", 0) : EMPTY_ARRAY;
        List<String> list = new ArrayList<>(path.length);
        for (var i = 1; i < path.length; i++) {
            list.add(path[i]);
        }
        list.add(nodeName);

        return list;
    }
}
