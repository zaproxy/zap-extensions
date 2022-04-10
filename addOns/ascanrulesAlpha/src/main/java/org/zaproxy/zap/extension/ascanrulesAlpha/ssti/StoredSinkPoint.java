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

import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.commonlib.http.ComparableResponse;

/**
 * Representation of a location where a given input is reflected after being sent in other location.
 * This can be used to get the state of the sink and store information about it. The main
 * information stored is the response to the original request and the response to a reference
 * request. This information may be useful to compare with the current state of the sink.
 *
 * @author DiogoMRSilva (2018)
 */
public class StoredSinkPoint implements SinkPoint {

    // Should be to the case there is no reference request defined because
    // the only reference is the original request
    private float similarityOfReference = 1;

    private ComparableResponse originalComparableResponse;

    private HttpMessage referenceHTTPRequest;
    private String referencePayload;
    private ComparableResponse referenceComparableResponse;

    private String sinkLocation;

    private HttpSender httpSender;

    private final String originalPayload;
    private final HttpMessage originalRequest;

    private static final int NOT_DEFINED_REQUEST_PENDING = -1;
    private static final Logger LOG = LogManager.getLogger(StoredSinkPoint.class);

    public StoredSinkPoint(HttpMessage originalSinkRequest, String payload) {
        originalRequest = originalSinkRequest;
        originalPayload = payload;
        sinkLocation = originalSinkRequest.getRequestHeader().getURI().toString();

        httpSender =
                new HttpSender(
                        Model.getSingleton().getOptionsParam().getConnectionParam(),
                        true,
                        HttpSender.ACTIVE_SCANNER_INITIATOR);
    }

    @Override
    public float getSimilarityToOriginal(HttpMessage request, String param, String payload) {
        HttpMessage updatedRequest = originalRequest.cloneRequest();
        try {
            httpSender.sendAndReceive(updatedRequest, false);
        } catch (IOException e) {
            LOG.debug(e);
        }
        return getOriginalComparableResponse()
                .compareWith(new ComparableResponse(updatedRequest, payload));
    }

    private ComparableResponse getOriginalComparableResponse() {
        if (originalComparableResponse == null) {
            originalComparableResponse = new ComparableResponse(originalRequest, originalPayload);
        }
        return originalComparableResponse;
    }

    @Override
    public float getSimilarityOfReference() {
        if (similarityOfReference == NOT_DEFINED_REQUEST_PENDING) {
            similarityOfReference =
                    getOriginalComparableResponse().compareWith(getReferenceComparableResponse());
        }
        return similarityOfReference;
    }

    private ComparableResponse getReferenceComparableResponse() {
        if (referenceComparableResponse == null) {
            referenceComparableResponse =
                    new ComparableResponse(referenceHTTPRequest, referencePayload);
        }
        return referenceComparableResponse;
    }

    @Override
    public String getCurrentStateInString(HttpMessage request, String param, String payload) {
        HttpMessage updatedRequest = originalRequest.cloneRequest();
        try {
            httpSender.sendAndReceive(updatedRequest, false);
        } catch (IOException e) {
            LOG.debug(e);
        }

        return updatedRequest.getResponseBody().toString()
                + updatedRequest.getResponseHeader().getHeadersAsString();
    }

    @Override
    public String getLocation() {
        return sinkLocation;
    }

    @Override
    public void addReferenceRequest(HttpMessage request, String param, String payload) {
        referenceHTTPRequest = originalRequest.cloneRequest();
        referencePayload = payload;
        try {
            httpSender.sendAndReceive(referenceHTTPRequest, false);
        } catch (IOException e) {
            LOG.debug(e);
        }

        similarityOfReference = NOT_DEFINED_REQUEST_PENDING;
    }
}
