/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.util.Collections;
import java.util.Map;
import org.apache.commons.collections.map.LRUMap;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

/**
 * MessageCache caches HTTP messages.
 *
 * @author 70pointer@gmail.com
 */
public class MessageCache {

    private static MessageCache instance;
    private HostProcess parent = null;

    @SuppressWarnings("unchecked")
    private Map<URI, HttpMessage> messagecache =
            Collections.synchronizedMap(new LRUMap(100)); // a map of 100 objects, synchronized

    private static Logger log = LogManager.getLogger(MessageCache.class);

    private MessageCache(HostProcess hostprocess) {
        log.debug("Initialising");
        parent = hostprocess;
    }

    public static synchronized MessageCache getSingleton(HostProcess hostprocess) {
        if (instance == null) createSingleton(hostprocess);
        return instance;
    }

    private static synchronized void createSingleton(HostProcess hostprocess) {
        if (instance == null) {
            instance = new MessageCache(hostprocess);
        }
    }

    /**
     * is a message cached for the given URI?
     *
     * @param uri
     * @return
     */
    public synchronized boolean isMessageCached(URI uri) {
        return messagecache.containsKey(uri);
    }

    /**
     * gets a HttpMessage for the requested URI, using basemsg as the base message. If the message
     * is available in the cache, return it. If not, retrieve it.
     *
     * @param uri the URI for which a httpMessage is being requested
     * @param basemsg the base message which will be used to construct new messages
     * @return a HttpMessage for the requested URI, using basemsg as the base message
     * @throws Exception
     */
    public synchronized HttpMessage getMessage(
            URI uri, HttpMessage basemsg, boolean followRedirects) throws Exception {
        if (!isMessageCached(uri)) {
            log.debug("URI '{}' is not in the message cache. Retrieving it.", uri);
            // request the file, then add the file to the cache
            // use the cookies from an original request, in case authorisation is required
            HttpMessage requestmsg = new HttpMessage(uri);
            try {
                requestmsg.setCookieParams(basemsg.getCookieParams());
            } catch (Exception e) {
                log.debug("Could not set the cookies from the base request: ", e);
            }
            requestmsg.getRequestHeader().setHeader(HttpHeader.IF_MODIFIED_SINCE, null);
            requestmsg.getRequestHeader().setHeader(HttpHeader.IF_NONE_MATCH, null);
            requestmsg.getRequestHeader().setContentLength(requestmsg.getRequestBody().length());
            parent.getHttpSender().sendAndReceive(requestmsg, followRedirects);
            parent.notifyNewMessage(requestmsg);
            // put the message in the cache
            messagecache.put(uri, requestmsg);
            log.debug("Put URI '{}' in the message cache.", uri);
        } else {
            log.debug("URI '{}' is cached in the message cache.", uri);
        }
        // and return the cached message.
        return messagecache.get(uri);
    }
}
