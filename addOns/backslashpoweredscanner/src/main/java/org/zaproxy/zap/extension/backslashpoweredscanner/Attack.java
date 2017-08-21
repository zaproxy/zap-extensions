/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.backslashpoweredscanner;

import java.util.HashMap;
import org.parosproxy.paros.network.HttpMessage;

/*
The technical challenge at the heart of Backslash Powered Scanner is recognising when an application's
response to two distinct probes is consistently different. A simple string comparison is utterly useless
on real world applications, which are notoriously dynamic. Responses are full of dynamic one-time tokens,
timestamps, cache-busters, and reflections of the supplied input.

Backslash Powered Scanner uses the simpler approach of calculating a number of attributes for each response,
and noting which ones are consistent across responses. Attributes include the status code, content type,
HTML structure, line count, word count, input reflection count, and the frequency of various keywords.

Attack contains the finger print of a HTTP response
*/

class Attack {
    private String anchor;
    private HttpMessage message;
    private String payload;
    private Probe probe;

    private HashMap<String, Object> fingerPrint = new HashMap<String, Object>();
    private KeywordsCountAnalysis keywordsCountAnalysis;
    private AttributeAnalysis attributeAnalysis;

    static final int UNINITIALISED = -1;
    static final int DYNAMIC = -2;
    static final int INCALCULABLE = -3;
    // responseReflections is used to determine if the response will reflect input
    private int responseReflections = UNINITIALISED;

    public Attack() {}

    public Attack(HttpMessage req, Probe probe, String payload, String anchor) {
        this.message = req;
        this.probe = probe;
        this.payload = payload;
        this.anchor = anchor;

        keywordsCountAnalysis = new KeywordsCountAnalysis(message.getResponseBody());
        attributeAnalysis = new AttributeAnalysis(message.getResponseHeader());
        updateResponseReflections(message, anchor);
    }

    public String getPayload() {
        return payload;
    }

    public HttpMessage getMessage() {
        return message;
    }

    public HashMap<String, Object> getFingerPrint() {
        fingerPrint.putAll(keywordsCountAnalysis.getKeywordsCounts());
        fingerPrint.putAll(attributeAnalysis.getInvariantAttributes());
        if (responseReflections != DYNAMIC) {
            fingerPrint.put("input_reflections", responseReflections);
        }
        return fingerPrint;
    }

    public void updateWith(Attack attack) {
        keywordsCountAnalysis.updateWith(attack.message.getResponseBody());
        attributeAnalysis.updateWith(attack.message.getResponseHeader());
        updateResponseReflections(attack.message, attack.anchor);
    }

    public void updateWith(HttpMessage msg, String anchor) {
        keywordsCountAnalysis.updateWith(msg.getResponseBody());
        attributeAnalysis.updateWith(msg.getResponseHeader());
        updateResponseReflections(msg, anchor);
    }

    public void updateResponseReflections(HttpMessage msg, String anchor) {
        if (anchor.equals("")) {
            responseReflections = INCALCULABLE;
        } else {
            int reflections =
                    Utilities.countMatches(msg.getRequestBody().getBytes(), anchor.getBytes());
            if (responseReflections == UNINITIALISED) {
                responseReflections = reflections;
            } else if (responseReflections != reflections && responseReflections != INCALCULABLE) {
                responseReflections = DYNAMIC;
            }
        }
    }
}
