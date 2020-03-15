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
package org.zaproxy.zap.extension.ascanrulesAlpha;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;

/** Contains methods to draw conclusions from responses */
public class Heuristics {

    /**
     * Detect if user is logged in from response body
     *
     * @param response response body
     * @return true, if user is deemed to be logged in
     */
    public static boolean isUserLoggedIn(String response) {
        Document doc = Jsoup.parse(response);
        Elements links = doc.select("a,submit,button");
        String[] patterns = new String[] {"log out", "sign out", "logout", "signout"};
        AtomicBoolean found = new AtomicBoolean(false);
        links.stream()
                .forEach(
                        link -> {
                            Arrays.asList(patterns).stream()
                                    .forEach(
                                            pattern -> {
                                                if (link.html().toLowerCase().contains(pattern)) {
                                                    found.set(true);
                                                }
                                            });
                        });
        return found.get();
    }

    /**
     * Concludes if a string is a valid JSON
     *
     * @param test String under test
     * @return true, if string is a valid JSON
     */
    public static boolean isJSONValid(String test) {
        try {
            new JSONObject(test);
        } catch (JSONException ex) {
            try {
                new JSONArray(test);
            } catch (JSONException ex1) {
                return false;
            }
        }
        return true;
    }
}
