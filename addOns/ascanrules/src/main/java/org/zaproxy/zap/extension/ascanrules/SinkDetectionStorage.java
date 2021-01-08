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

import com.googlecode.concurrenttrees.radix.node.concrete.DefaultCharArrayNodeFactory;
import com.googlecode.concurrenttrees.radix.node.concrete.voidvalue.VoidValue;
import com.googlecode.concurrenttrees.radixinverted.ConcurrentInvertedRadixTree;
import com.googlecode.concurrenttrees.radixinverted.InvertedRadixTree;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.ParamSinksUtils.DatabaseMessagesStorage;
import org.zaproxy.addon.commonlib.ParamSinksUtils.MessagesStorage;

public class SinkDetectionStorage {

    private InvertedRadixTree<VoidValue> seenValues;
    private Map<String, Set<Integer>> possibleSinksForValues;
    private Map<Integer, Integer> messagesHashToStorageIds;
    private static MessagesStorage messagesStorage;

    public SinkDetectionStorage() {
        seenValues = new ConcurrentInvertedRadixTree<VoidValue>(new DefaultCharArrayNodeFactory());
        possibleSinksForValues = Collections.synchronizedMap(new HashMap<>());
        messagesHashToStorageIds = Collections.synchronizedMap(new HashMap<>());
        messagesStorage = new DatabaseMessagesStorage();
    }

    public void setMessagesStorage(MessagesStorage storage) {
        messagesStorage = storage;
    }

    public void addSeenValue(String value) {
        seenValues.put(value, VoidValue.SINGLETON);
    }

    public Set<String> getSeenValuesContainedInString(String text) {
        Set<String> valuesSeenInText = new HashSet<>();
        for (CharSequence charSequence : seenValues.getKeysContainedIn(text)) {
            valuesSeenInText.add((String) charSequence);
        }
        return valuesSeenInText;
    }

    public void addPossibleSinkForValue(String value, HttpMessage sink) {
        synchronized (possibleSinksForValues) {
            Set<Integer> sinksForValue = possibleSinksForValues.get(value);

            if (sinksForValue == null) {
                sinksForValue = new HashSet<>();
                possibleSinksForValues.put(value, sinksForValue);
            }
            boolean newMessage = sinksForValue.add(sink.hashCode());
            if (newMessage) {
                int msgId = messagesStorage.storeMessage(sink);
                messagesHashToStorageIds.put(sink.hashCode(), msgId);
            }
        }
    }

    public Set<HttpMessage> getPossibleSinksForValue(String value) {
        Set<Integer> possibleSinks = possibleSinksForValues.get(value);
        if (possibleSinks == null) return Collections.emptySet();

        Set<HttpMessage> sinkMsgs = new HashSet<>();
        for (int msgHash : possibleSinks) {
            int msgId = messagesHashToStorageIds.get(msgHash);
            HttpMessage msg = messagesStorage.getMessage(msgId);
            if (msg != null) {
                sinkMsgs.add(msg);
            }
        }
        return sinkMsgs;
    }
}
