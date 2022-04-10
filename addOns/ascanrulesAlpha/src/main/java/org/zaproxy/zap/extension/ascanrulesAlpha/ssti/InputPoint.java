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

import java.util.ArrayList;
import java.util.List;
import org.parosproxy.paros.network.HttpMessage;

/**
 * The InputPoint objects represents an input point of an application and stores the locations
 * (sinks) where that input is going to be reflected.
 *
 * @author DiogoMRSilva (2018)
 */
public class InputPoint {
    private final List<SinkPoint> sinkPoints;

    public InputPoint() {
        sinkPoints = new ArrayList<>();
    }

    public List<SinkPoint> getSinkPoints() {
        return sinkPoints;
    }

    public List<SinkPoint> addSinkPoint(SinkPoint sink) {
        sinkPoints.add(sink);
        return sinkPoints;
    }

    public List<SinkPoint> removeSinkPoint(SinkPoint sink) {
        sinkPoints.remove(sink);
        return sinkPoints;
    }

    public List<SinkPoint> addReferenceReqToAllSinkPoints(
            HttpMessage request, String param, String payload) {
        for (SinkPoint sp : sinkPoints) {
            sp.addReferenceRequest(request, param, payload);
        }
        return sinkPoints;
    }
}
