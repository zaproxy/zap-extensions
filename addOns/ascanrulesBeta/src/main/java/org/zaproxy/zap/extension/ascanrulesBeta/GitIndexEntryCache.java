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

/**
 * GitEntryCache caches Git Index Entries
 *
 * @author 70pointer@gmail.com
 */
public class GitIndexEntryCache {

    private static GitIndexEntryCache instance;

    @SuppressWarnings("unchecked")
    private Map<URI, Map<URI, String>> gitIndexMap =
            Collections.synchronizedMap(new LRUMap(20)); // max: 20 Git index files (LRU)

    private static Logger log = LogManager.getLogger(GitIndexEntryCache.class);

    private GitIndexEntryCache() {
        log.debug("Initialising the Git Index Entry Cache");
    }

    public static synchronized GitIndexEntryCache getSingleton() {
        if (instance == null) createSingleton();
        return instance;
    }

    private static synchronized void createSingleton() {
        if (instance == null) {
            instance = new GitIndexEntryCache();
        }
    }

    /**
     * is a Git index cached for the given Git index URI?
     *
     * @param uri
     * @return
     */
    public synchronized boolean isIndexCached(URI gitIndexUri) {
        return gitIndexMap.containsKey(gitIndexUri);
    }

    /**
     * is a Git index entry cached for the given Git index URI, and Git Index entry URI?
     *
     * @param uri
     * @return
     */
    public synchronized boolean isIndexEntryCached(URI gitIndexUri, URI gitIndexEntryUri) {
        if (!gitIndexMap.containsKey(gitIndexUri)) {
            return false;
        }
        return gitIndexMap.get(gitIndexUri).containsKey(gitIndexEntryUri);
    }

    /**
     * puts the Git Index and Git Index Entry in a map
     *
     * @param gitIndexUri
     * @param gitIndexEntryUri
     */
    @SuppressWarnings("unchecked")
    public synchronized void putIndexEntry(URI gitIndexUri, URI gitIndexEntryUri, String gitSHA1) {
        Map<URI, String> indexEntryMap;
        if (gitIndexMap.containsKey(gitIndexUri)) {
            indexEntryMap = gitIndexMap.get(gitIndexUri);
        } else {
            indexEntryMap =
                    Collections.synchronizedMap(
                            new LRUMap(1000)); // max: 1000 Git index entries (LRU)
        }
        indexEntryMap.put(gitIndexEntryUri, gitSHA1);
        gitIndexMap.put(gitIndexUri, indexEntryMap);
    }

    /**
     * gets the SHA1 for a Git Index and Git Index Entry
     *
     * @param gitIndexUri
     * @param gitIndexEntryUri
     * @return
     */
    public synchronized String getIndexEntry(URI gitIndexUri, URI gitIndexEntryUri) {
        if (gitIndexMap.containsKey(gitIndexUri)) {
            return gitIndexMap.get(gitIndexUri).get(gitIndexEntryUri);
        } else {
            return null;
        }
    }
}
