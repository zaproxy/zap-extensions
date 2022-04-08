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
package org.zaproxy.zap.extension.ascanrulesAlpha.ssti;

import org.parosproxy.paros.network.HttpMessage;

/**
 * Representation of a location where a given input is shown after being sent. This can be used to
 * get the state of the sink and compare it with previous states. The classes implementing this
 * interface should somehow be a able to compare the effect of making a request with the effect
 * caused by previous ones more specifically the original request and one the programmer chooses as
 * reference.
 *
 * @author DiogoMRSilva (2018)
 */
public interface SinkPoint {

    /**
     * Compare the effect that {@code request} with the {@code payload} in {@code param} makes in
     * the sink with the effect that the original payload made.
     *
     * @param request request which may have caused a change in the sink
     * @param param the parameter where the payload was inserted
     * @param payload the payload that was send
     */
    float getSimilarityToOriginal(HttpMessage request, String param, String payload);

    /** Returns the similarity that is usual when a payload different from the original is sent */
    float getSimilarityOfReference();

    /**
     * Get a string representing the current state of the sink caused by the {@code request} with
     * the {@code payload} in {@code param}
     *
     * @param request request which may have caused a change in the sink
     * @param param the parameter where the payload was inserted
     * @param payload the payload that was send
     */
    String getCurrentStateInString(HttpMessage request, String param, String payload);

    /** Get a string representing the location of the sink */
    String getLocation();

    /**
     * Set {@code request} as reference request
     *
     * @param request request which may have caused a change in the sink
     * @param param the parameter where the payload was inserted
     * @param payload the payload that was send
     */
    void addReferenceRequest(HttpMessage request, String param, String payload);
}
