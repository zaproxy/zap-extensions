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
package org.zaproxy.zap.extension.ascanrules.timing;

import java.util.function.Function;

/**
 * Utility class to host time-based blind detection algorithms.
 *
 * @since 1.11.0
 */
public class TimingUtils {

    /**
     * Sends time-based blind requests and analyze the response times using simple linear
     * regression. If this returns true, then an increment in payload delay positively correlates to
     * an increment in actual delay, indicating the presence of an injection vulnerability. This
     * particular implementation is designed to send as few requests as possible, and will return
     * false immediately if the correlation dips too low or if the actual delay is less than the
     * expected delay, so it will not necessarily send one request for each input time.
     *
     * @param expectedTimes the delays we will request, in order.
     * @param requestSender function that takes in the expected time, sends the request, and returns
     *     the actual delay.
     * @param correlationErrorRange the interval of acceptance for the regression correlation. for
     *     example, input 0.2 will return true if 0.8 < correlation
     * @param slopeErrorRange the interval of acceptance for the regression slope. for example,
     *     input 0.2 will return true if 0.8 < slope < 1.2
     * @return true if the response times correlate linearly, false otherwise.
     * @throws IllegalArgumentException if less than 3 expectedTimes are provided.
     */
    public static boolean checkTimingDependence(
            double[] expectedTimes,
            Function<Double, Double> requestSender,
            double correlationErrorRange,
            double slopeErrorRange) {
        if (expectedTimes.length < 3)
            throw new IllegalArgumentException("requires at least 3 expected times, (5+ rec)");

        OnlineSimpleLinearRegression regression = new OnlineSimpleLinearRegression();

        // only iterate up to the provided expectedTimes
        for (double x : expectedTimes) {
            // apply the provided function to get the dependent variable
            double y = requestSender.apply(x);

            // this is not a general assertion, but in our case, we want to stop early
            // if the expected delay isn't at LEAST as much as the requested delay
            if (y < x) return false;

            // update the regression computation with a new time pair
            regression.addPoint(x, y);

            // failure case if we're clearly not even close
            if (!regression.isWithinConfidence(0.3, 1.0, 0.5)) return false;
        }

        // we want the slope and correlation to both be reasonably close to 1
        // if the correlation is bad, the relationship is non-linear
        // if the slope is bad, the relationship is not positively 1:1
        return regression.isWithinConfidence(correlationErrorRange, 1.0, slopeErrorRange);
    }
}
