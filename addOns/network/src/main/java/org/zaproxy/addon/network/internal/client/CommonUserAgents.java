/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Provides common user-agent values. */
public final class CommonUserAgents {

    private static final String COMMENT_TOKEN = "#";

    private static final Map<String, String> SYSTEM_TO_USER_AGENT;
    private static final Map<String, String> USER_AGENT_TO_SYSTEM;

    private static final Logger logger = LogManager.getLogger(CommonUserAgents.class);

    static {
        SYSTEM_TO_USER_AGENT = new HashMap<>();
        USER_AGENT_TO_SYSTEM = new HashMap<>();

        try (InputStream is = CommonUserAgents.class.getResourceAsStream("common-user-agents.txt");
                BufferedReader reader =
                        new BufferedReader(new InputStreamReader(is, StandardCharsets.US_ASCII))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty() || line.startsWith(COMMENT_TOKEN)) {
                    continue;
                }

                String[] array = line.split("\t");
                if (array.length != 3) {
                    logger.error("Unexpected format in line: {}", line);
                } else {
                    SYSTEM_TO_USER_AGENT.put(array[2], array[1]);
                    USER_AGENT_TO_SYSTEM.put(array[1], array[2]);
                }
            }

        } catch (IOException e) {
            logger.error(e.getMessage(), e);
        }
    }

    private CommonUserAgents() {}

    public static String getUserAgentFromSystem(String system) {
        return SYSTEM_TO_USER_AGENT.get(system);
    }

    public static String getSystemFromUserAgent(String userAgent) {
        return USER_AGENT_TO_SYSTEM.get(userAgent);
    }

    public static String[] getSystems() {
        String[] names = SYSTEM_TO_USER_AGENT.keySet().toArray(new String[0]);
        Arrays.sort(names);
        return names;
    }
}
