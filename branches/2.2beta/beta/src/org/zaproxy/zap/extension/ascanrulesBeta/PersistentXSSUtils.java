/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;

public class PersistentXSSUtils {

    private static int uniqueIndex = 0;
    public static String PXSS_PREFIX = "zApPX";
    public static String PXSS_POSTFIX = "sS";
    private static Map<String, UserDataSource> map = new HashMap<String, UserDataSource>();
    private static Map<String, HashSet<HttpMessage>> sourceToSinks = new HashMap<String, HashSet<HttpMessage>>();
    private static Logger log = Logger.getLogger(PersistentXSSUtils.class);

    public static String getUniqueValue(HttpMessage msg, String param) {
        String uniqueVal = PXSS_PREFIX + uniqueIndex++ + PXSS_POSTFIX;
        map.put(uniqueVal, new UserDataSource(msg, param));
        return uniqueVal;
    }

    public static void testForSink(HttpMessage msg) {
        String body = msg.getResponseBody().toString();
        int start = body.indexOf(PXSS_PREFIX);
        if (start > 0) {
            int end = body.indexOf(PXSS_POSTFIX, start);
            if (end > 0) {
                String uniqueVal = body.substring(start, end + PXSS_POSTFIX.length());
                UserDataSource source = map.get(uniqueVal);
                if (source != null) {
                    setSinkForSource(source, msg);
                }
            }
        }
    }

    public static void setSinkForSource(HttpMessage sourceMsg, String param, HttpMessage sinkMsg) {
        if (log.isDebugEnabled()) {
            log.debug("setSinkForSource src=" + sourceMsg.getRequestHeader().getURI()
                    + " param=" + param + " sink=" + sinkMsg.getRequestHeader().getURI());
        }
        setSinkForSource(new UserDataSource(sourceMsg, param), sinkMsg);
    }

    public static void setSinkForSource(UserDataSource source, HttpMessage sinkMsg) {
        HashSet<HttpMessage> sinks = sourceToSinks.get(source);
        if (sinks == null) {
            sinks = new HashSet<HttpMessage>();
        }
        sinks.add(sinkMsg);
        sourceToSinks.put(source.toString(), sinks);
    }

    public static Set<HttpMessage> getSinksForSource(HttpMessage sourceMsg, String param) {
        UserDataSource source = new UserDataSource(sourceMsg, param);
        if (log.isDebugEnabled()) {
            log.debug("getSinkForSource src=" + sourceMsg.getRequestHeader().getURI()
                    + " param=" + param + " sinks=" + sourceToSinks.get(source.toString()));
        }
        return sourceToSinks.get(source.toString());
    }
}
