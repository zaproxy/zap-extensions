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
import org.zaproxy.addon.commonlib.http.ComparableResponse;

/**
 * Representation of the response to a given request. This can be used to get the state of the sink
 * and store information about it. The main information stored is the response to the original
 * request and the response to a reference request. This information may be useful to compare with
 * the current state of the sink.
 *
 * @author DiogoMRSilva (2018)
 */
public class ReflectedSinkPoint implements SinkPoint {
    private float similarityOfReference = 1;

    private ComparableResponse originalComparableResponse;

    private HttpMessage referenceHTTPRequest;
    private String referencePayload;
    private ComparableResponse referenceComparableResponse;

    private String sinkLocation;

    private final HttpMessage originalRequest;
    private final String originalPayload;

    private static final int NOT_DEFINED = -1;

    public ReflectedSinkPoint(HttpMessage request, String payload) {
        this.originalRequest = request;
        this.originalPayload = payload;
        this.sinkLocation = request.getRequestHeader().getURI().toString();
    }

    public ReflectedSinkPoint(
            HttpMessage request,
            String payload,
            HttpMessage referenceRequest,
            String referencePayload) {
        this(request, payload);

        this.referenceHTTPRequest = referenceRequest;
        this.referencePayload = referencePayload;

        this.sinkLocation = request.getRequestHeader().getURI().toString();
    }

    private ComparableResponse getOriginalComparableResponse() {
        if (originalComparableResponse == null) {
            originalComparableResponse = new ComparableResponse(originalRequest, originalPayload);
        }
        return originalComparableResponse;
    }

    private ComparableResponse getReferenceComparableResponse() {
        if (referenceComparableResponse == null) {
            referenceComparableResponse =
                    new ComparableResponse(referenceHTTPRequest, referencePayload);
        }
        return referenceComparableResponse;
    }

    @Override
    public float getSimilarityToOriginal(HttpMessage request, String param, String payload) {
        return getOriginalComparableResponse()
                .compareWith(new ComparableResponse(request, payload));
    }

    @Override
    public float getSimilarityOfReference() {
        if (similarityOfReference == NOT_DEFINED) {
            similarityOfReference =
                    getOriginalComparableResponse().compareWith(getReferenceComparableResponse());
        }
        return similarityOfReference;
    }

    @Override
    public String getCurrentStateInString(HttpMessage request, String param, String payload) {
        // Headers should also be checked, example: CVE-2018-14716
        return request.getResponseBody().toString()
                + request.getResponseHeader().getHeadersAsString();
    }

    @Override
    public String getLocation() {
        return sinkLocation;
    }

    @Override
    public void addReferenceRequest(HttpMessage request, String param, String payload) {
        referenceHTTPRequest = request;
        referencePayload = payload;
        referenceComparableResponse = null;
        similarityOfReference = NOT_DEFINED;
    }
}
