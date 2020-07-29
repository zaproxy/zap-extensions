/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.apache.commons.collections.map.ReferenceMap;
import org.apache.log4j.Logger;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;

public class PersistentXssUtils {

    private static int uniqueIndex;
    public static String PXSS_PREFIX = "zApPX";
    public static String PXSS_POSTFIX = "sS";
    private static Map<String, UserDataSource> map;
    private static Map<String, HashSet<Integer>> sourceToSinks;
    /**
     * A {@code Map} to cache the URIs used by source messages ({@code UserDataSource}).
     *
     * <p>The URIs will be different {@code String} objects (see {@code URI#toString()}) while
     * representing the same URI. This happens for each parameter attacked per source message which
     * would lead to multiple duplicated {@code String}s.
     *
     * @see #getCachedItem(Map, String)
     * @see UserDataSource#UserDataSource(HttpMessage, String)
     * @see org.apache.commons.httpclient.URI#toString()
     */
    private static Map<String, String> cachedUris;
    /**
     * A {@code Map} to cache the parameter names used by source messages ({@code UserDataSource}).
     *
     * <p>The parameter names will be different {@code String} objects (see {@code Variant}
     * implementations) while representing the same parameter names. This happens for each parameter
     * attacked per source message which would lead to multiple duplicated {@code String}s.
     *
     * @see #getCachedItem(Map, String)
     * @see UserDataSource#UserDataSource(HttpMessage, String)
     * @see org.parosproxy.paros.core.scanner.Variant
     */
    private static Map<String, String> cachedParams;

    private static Logger log = Logger.getLogger(PersistentXssUtils.class);

    static {
        reset();
    }

    public static String getUniqueValue(HttpMessage msg, String param) {
        String uniqueVal = PXSS_PREFIX + uniqueIndex++ + PXSS_POSTFIX;
        map.put(uniqueVal, new UserDataSource(msg, param));
        return uniqueVal;
    }

    public static void testForSink(HttpMessage msg) {
        String body = msg.getResponseBody().toString();
        int start = body.indexOf(PXSS_PREFIX);
        while (start > 0) {
            int end = body.indexOf(PXSS_POSTFIX, start);
            if (end > 0) {
                String uniqueVal = body.substring(start, end + PXSS_POSTFIX.length());
                UserDataSource source = map.get(uniqueVal);
                if (source != null) {
                    setSinkForSource(source, msg);
                }
                start = body.indexOf(PXSS_PREFIX, end);
            } else {
                break;
            }
        }
    }

    public static void setSinkForSource(HttpMessage sourceMsg, String param, HttpMessage sinkMsg) {
        setSinkForSource(new UserDataSource(sourceMsg, param), sinkMsg);
    }

    private static void setSinkForSource(UserDataSource source, HttpMessage sinkMsg) {
        if (log.isDebugEnabled()) {
            log.debug(
                    "setSinkForSource src="
                            + source.getUri()
                            + " param="
                            + source.getParam()
                            + " sink="
                            + sinkMsg.getRequestHeader().getURI());
        }
        HashSet<Integer> sinks = sourceToSinks.get(source.toString());
        if (sinks == null) {
            sinks = new HashSet<>();
        }
        try {
            HistoryReference hRef =
                    new HistoryReference(
                            Model.getSingleton().getSession(),
                            HistoryReference.TYPE_SCANNER_TEMPORARY,
                            sinkMsg);
            sinks.add(Integer.valueOf(hRef.getHistoryId()));
            sourceToSinks.put(source.toString(), sinks);
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            log.warn("Failed to persist HTTP message to database:", e);
        }
    }

    /**
     * Gets the IDs of the sink messages for the given message and parameter.
     *
     * @param sourceMsg the source message
     * @param param the parameter being tested
     * @return the IDs of the messages that match the given source message and parameter, {@code
     *     null} if no matches
     * @see #getMessage(int)
     */
    public static Set<Integer> getSinksIdsForSource(HttpMessage sourceMsg, String param) {
        UserDataSource source = new UserDataSource(sourceMsg, param);
        if (log.isDebugEnabled()) {
            log.debug(
                    "getSinksIdsForSource src="
                            + source.getUri()
                            + " param="
                            + param
                            + " sinks="
                            + sourceToSinks.get(source.toString()));
        }
        return sourceToSinks.get(source.toString());
    }

    /** Resets the state of {@code PersistentXssUtils}. */
    @SuppressWarnings("unchecked")
    public static void reset() {
        uniqueIndex = 0;
        map = new HashMap<>();
        sourceToSinks = new HashMap<>();
        cachedUris =
                Collections.synchronizedMap(new ReferenceMap(ReferenceMap.SOFT, ReferenceMap.SOFT));
        cachedParams =
                Collections.synchronizedMap(new ReferenceMap(ReferenceMap.SOFT, ReferenceMap.SOFT));
    }

    /**
     * Gets the message with the given ID.
     *
     * @param sinkMsgId the ID of the message
     * @return the message with the given ID, or {@code null} if it was not possible to obtain the
     *     message
     * @see #getSinksIdsForSource(HttpMessage, String)
     */
    public static HttpMessage getMessage(int sinkMsgId) {
        try {
            return new HistoryReference(sinkMsgId).getHttpMessage();
        } catch (HttpMalformedHeaderException | DatabaseException e) {
            log.warn("Failed to read HTTP message from database:", e);
        }
        return null;
    }

    private static String getCachedItem(Map<String, String> map, String item) {
        String cachedItem = map.get(item);
        if (cachedItem != null) {
            return cachedItem;
        }
        map.put(item, item);
        return item;
    }

    private static class UserDataSource {

        private final String uri;
        private final String param;
        private final String stringRepresentation;

        public UserDataSource(HttpMessage sourceMsg, String param) {
            super();
            this.uri = getCachedItem(cachedUris, sourceMsg.getRequestHeader().getURI().toString());
            this.param = getCachedItem(cachedParams, param);
            this.stringRepresentation = uri + "#" + param;
        }

        @Override
        public String toString() {
            return stringRepresentation;
        }

        public String getUri() {
            return uri;
        }

        public String getParam() {
            return param;
        }
    }
}
