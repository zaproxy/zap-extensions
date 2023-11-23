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
package org.zaproxy.addon.client;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.network.HttpHeader;
import org.zaproxy.zap.model.NameValuePair;
import org.zaproxy.zap.model.ParameterParser;

public class ClientUtils {

    public static final String LOCAL_STORAGE = "localStorage";
    public static final String SESSION_STORAGE = "sessionStorage";

    public static List<String> urlToNodes(String url, ParameterParser paramParser) {
        if (url == null) {
            throw new IllegalArgumentException("The url parameter should not be null");
        }
        // Parse the URL into its component pieces
        String urlLc = url.toLowerCase(Locale.ROOT);
        if (!(urlLc.startsWith(HttpHeader.SCHEME_HTTP)
                || urlLc.startsWith(HttpHeader.SCHEME_HTTPS))) {
            throw new IllegalArgumentException(
                    "The url parameter must start with 'http://' or 'https://' - was " + urlLc);
        }
        List<String> nodes = new ArrayList<>();
        int offset = url.indexOf("//") + 2;
        String prefix = url.substring(0, offset);
        String theRest = url.substring(offset);

        // Save the fragment for the end
        String fragment = null;
        offset = theRest.indexOf('#');
        if (offset > 0) {
            fragment = theRest.substring(offset);
            theRest = theRest.substring(0, offset);
        }

        // Handle the query next
        String query = null;
        offset = theRest.indexOf('?');
        if (offset > 0) {
            query = theRest.substring(offset + 1);
            theRest = theRest.substring(0, offset);
        }

        for (String element : theRest.split("/")) {
            nodes.add(prefix + element);
            prefix = "";
        }

        prefix = theRest.endsWith("/") ? "/" : "";

        if (StringUtils.isNotBlank(query)) {
            if (StringUtils.isBlank(prefix) && nodes.size() > 1) {
                // The last element is a page not a path, so append to it
                String page = nodes.remove(nodes.size() - 1);
                nodes.add(page + paramsToNodeName(query, paramParser));
            } else {
                nodes.add(prefix + paramsToNodeName(query, paramParser));
                prefix = "";
            }
        }
        if (fragment != null) {
            if (fragment.length() == 1) {
                // Just the #, nothing else
                nodes.add(prefix + fragment);
            } else {
                nodes.add(prefix + '#');
                nodes.add(fragment.substring(1));
            }
            prefix = "";
        }
        if (StringUtils.isNotBlank(prefix)) {
            nodes.add(prefix);
        }

        return nodes;
    }

    protected static String paramsToNodeName(String queryString, ParameterParser paramParser) {
        StringBuilder sb = new StringBuilder();
        List<NameValuePair> params = paramParser.parseParameters(queryString);
        Collections.sort(params, (a, b) -> a.getName().compareTo(b.getName()));
        sb.append('(');
        boolean first = true;
        for (NameValuePair nv : params) {
            if (first) {
                first = false;
            } else {
                sb.append(',');
            }
            sb.append(nv.getName());
        }
        sb.append(')');
        return sb.toString();
    }

    public static void setClipboardContents(String str) {
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(new StringSelection(str), null);
    }

    public static String stripUrlFragment(String url) {
        if (url == null) {
            throw new IllegalArgumentException("The url parameter should not be null");
        }
        int fragmentOffset = url.indexOf('#');
        if (fragmentOffset > 0) {
            return url.substring(0, fragmentOffset);
        }
        return url;
    }
}
