/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.paramminer;

import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URIException;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;

/** A utility class for URL bruteforce related operations for the paramminer add-on. */
public class UrlUtils {
    private static Logger logger = LogManager.getLogger(UrlUtils.class);
    /**
     * Returns a List of all parameters to be used from a given wordlist file.
     *
     * @param path the path to the wordlist.
     * @return a List<String> of all parameters to be used from a given wordlist file.
     */
    public static List<String> read(Path path) {
        List<String> params = new ArrayList<>();
        try (BufferedReader br = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line;
            while ((line = br.readLine()) != null) {
                params.add(StringUtils.strip(line));
            }
        } catch (Exception e) {
            logger.error(e);
        }
        return params;
    }

    /**
     * Returns a Map of all parameters to be used from a given wordlist along with a fuzzy number
     * key.
     *
     * @param list the List of all parameters to be used from a given wordlist.
     * @return a Map<String, String> of all parameters to be used from a given wordlist along with a
     *     fuzzy number key.
     */
    public static Map<String, String> populate(List<String> list) {
        Map<String, String> map = new HashMap<>();
        String value;
        String paramName;
        for (int i = 0; i < list.size(); i++) {
            paramName = list.get(i);
            String fuzzy = Integer.toString(i);
            value = StringUtils.repeat("1", (6 - fuzzy.length())) + fuzzy;
            map.put(paramName, value);
        }
        return map;
    }

    /**
     * Divides a given Map of parameters into given parts.
     *
     * @param parts the number of parts to divide the Map into.
     * @param map the Map of parameters to be divided.
     * @return a List<Map<String, String>> of parameters divided into given parts.
     */
    public static List<Map<String, String>> slice(Map<String, String> map, int parts) {
        int size = map.size();
        if (size == 0) {
            return new ArrayList<>(0);
        }
        List<Map<String, String>> list = new ArrayList<>(parts);
        List<Entry<String, String>> items = new ArrayList<>(map.entrySet());
        int k = size / parts;
        int m = size % parts;
        for (int i = 0; i < parts; i++) {
            int x = i * k + Math.min(i, m);
            int y = (i + 1) * k + Math.min(i + 1, m);
            Map<String, String> newMap = new HashMap<>();
            for (int j = x; j < y; j++) {
                newMap.put(items.get(j).getKey(), items.get(j).getValue());
            }
            list.add(newMap);
        }
        return list;
    }

    /**
     * Returns a query string from a given parameter map. The query string is not encoded.
     *
     * @param map the Map of parameters to be used.
     * @return a query string from a given parameter map.
     */
    public static String createQueryString(Map<String, String> map) {
        StringBuilder sb = new StringBuilder();
        sb.append('?');
        for (Entry<String, String> entry : map.entrySet()) {
            sb.append(entry.getKey()).append('=').append(entry.getValue()).append('&');
        }
        sb.deleteCharAt(sb.length() - 1);
        return sb.toString();
    }

    /**
     * Returns a List of parameter maps having more than one parameter, while setting the used up or
     * confirmed parameters.
     *
     * @param parameters List of parameter maps.
     * @param usable List of usable parameter maps.
     * @return a List of parameter maps having more than one parameter.
     */
    public static List<Map<String, String>> confirmUsableParameters(
            List<Map<String, String>> parameters, List<Map<String, String>> usable) {
        List<Map<String, String>> paramGroups = new ArrayList<>();
        for (Map<String, String> param : parameters) {
            if (param.size() == 1) {
                usable.add(param);
            } else {
                paramGroups.add(param);
            }
        }
        return paramGroups;
    }

    /**
     * Removes all html tags from a given content string.
     *
     * @param str the content string to be stripped.
     * @return a string without html tags.
     */
    public static String removeTags(String str) {
        Source source = new Source(str);
        return source.getTextExtractor().setIncludeAttributes(true).toString();
    }

    /**
     * Returns a list of lines that are comon between two content Strings.
     *
     * @param body1 the first content string.
     * @param body2 the second content string.
     * @return a list of lines that are comon between two content Strings.
     */
    public static List<String> diffMap(String body1, String body2) {
        List<String> diff = new ArrayList<>();
        String[] body1Lines = StringUtils.split(body1, "\n");
        String[] body2Lines = StringUtils.split(body2, "\n");
        for (int i = 0; i < body1Lines.length; i++) {
            if (body1Lines[i].equalsIgnoreCase(body2Lines[i])) {
                diff.add(StringUtils.strip(body1Lines[i]));
            }
        }
        return diff;
    }

    public static String getPath(HttpMessage msg) {
        String path = "";
        try {
            path = msg.getRequestHeader().getURI().getPath();
        } catch (URIException e) {
            logger.warn(
                    "Invalid URL: {} Exception raised: {}",
                    msg.getRequestHeader().getURI().toString(),
                    e);
        }
        return path;
    }

    /**
     * Decides some factors based on which requests can be compared and vulnberable paramteres can
     * be decided.
     *
     * @param msg1 the first HttpMessage.
     * @param msg2 the second HttpMessage.
     * @param param the parameter to be used.
     * @param value the value of the parameter.
     * @param wordlist the wordlist to be used.
     * @return a Factors object.
     */
    public static Factors defineFactors(
            HttpMessage msg1, HttpMessage msg2, String param, String value, List<String> wordlist) {
        Factors factors = new Factors();

        String body1 = msg1.getResponseBody().toString();
        String body2 = msg2.getResponseBody().toString();

        if (msg1.getResponseHeader().getStatusCode() == msg2.getResponseHeader().getStatusCode()) {
            factors.setSameCode(true);
        }

        if (msg1.getResponseHeader().getHeaders().equals(msg2.getResponseHeader().getHeaders())) {
            factors.setHeaders(msg1.getResponseHeader().getHeaders());
        }

        if (body1.equalsIgnoreCase(body2)) {
            factors.setSameBody(true);
        } else if (StringUtils.countMatches(body1, '\n') == StringUtils.countMatches(body2, '\n')) {
            factors.setLinesNumValue(StringUtils.countMatches(body1, '\n'));
        } else if (removeTags(body1).equalsIgnoreCase(removeTags(body2))) {
            factors.setPlainText(removeTags(body1));
        } else if (!body1.isEmpty()
                && !body2.isEmpty()
                && (StringUtils.countMatches("\\n", body1)
                        == StringUtils.countMatches("\\n", body2))) {
            factors.setDiffMapLines(diffMap(body1, body2));
        }

        String path1 = getPath(msg1);
        String path2 = getPath(msg2);
        if (path1.equalsIgnoreCase(path2)) {
            factors.setSameRedirectPath(path1);
        }

        if (!body2.contains(param)) {
            List<String> missing = new ArrayList<>();
            for (String word : wordlist) {
                if (body1.contains(word)) {
                    missing.add(word);
                }
            }
            factors.setMissingParams(missing);
        }

        if (!body2.contains(value)) {
            factors.setValueMissing(true);
        }
        return factors;
    }
}
