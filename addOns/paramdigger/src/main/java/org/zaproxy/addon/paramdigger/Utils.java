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
package org.zaproxy.addon.paramdigger;

import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import net.sf.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** A utility class for URL bruteforce related operations for the param digger add-on. */
public class Utils {

    private static Logger logger = LogManager.getLogger(Utils.class);
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
     * Returns an XML string from a given parameter map. The XML string is not encoded.
     *
     * @param map the Map of parameters to be used.
     * @return an XML string from a given parameter map.
     */
    public static String createXmlString(Map<String, String> map) {
        StringBuilder sb = new StringBuilder();
        for (Entry<String, String> entry : map.entrySet()) {
            sb.append('<');
            sb.append(entry.getKey());
            sb.append('>');
            sb.append(entry.getValue());
            sb.append("</");
            sb.append(entry.getKey());
            sb.append('>');
        }
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

    public static String createJsonString(Map<String, String> params) {
        JSONObject json = new JSONObject();
        json.accumulateAll(params);
        return json.toString();
    }
}
