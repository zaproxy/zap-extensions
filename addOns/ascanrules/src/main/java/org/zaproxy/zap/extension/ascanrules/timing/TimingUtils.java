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

import java.io.IOException;

/** Utility class to host time-based blind detection algorithms. */
public class TimingUtils {

    // Minimum requests required for a meaningful result
    private static final int MINIMUM_REQUESTS = 3;

    /**
     * Sends time-based blind requests and analyze the response times using simple linear
     * regression. If this returns true, then an increment in payload delay positively correlates to
     * an increment in actual delay, indicating the presence of an injection vulnerability. This
     * particular implementation is designed to send as few requests as possible, and will return
     * false immediately if the correlation dips too low or if the actual delay is less than the
     * expected delay. This implementation also requires a minimum number of request data points to
     * prevent false positives where a website only responded once or twice within the time limit.
     *
     * @param requestsLimit the hard limit on how many times at most requestSender will be called.
     *     in practice, if there is a correlation, within 0-2 to this number of requests will be
     *     sent. if there is no correlation, most likely far fewer.
     * @param secondsLimit the soft limit on how much total time at most should be spent on sending
     *     requests before forcing a verdict. the limit is necessarily soft since we don't control
     *     how long requestSender takes to resolve.
     * @param requestSender function that takes in the expected time, sends the request, and returns
     *     the actual delay.
     * @param correlationErrorRange the interval of acceptance for the regression correlation. for
     *     example, input 0.2 will return true if 0.8 < correlation
     * @param slopeErrorRange the interval of acceptance for the regression slope. for example,
     *     input 0.2 will return true if 0.8 < slope < 1.2
     * @return true if the response times correlate linearly, false otherwise.
     * @throws IllegalArgumentException if less than 3 is provided as the requestsLimit OR if less
     *     than 5 is provided as the secondsLimit
     * @throws IOException if the RequestSender throws an IOException, it will bubble up here
     */
    public static boolean checkTimingDependence(
            int requestsLimit,
            double secondsLimit,
            RequestSender requestSender,
            double correlationErrorRange,
            double slopeErrorRange)
            throws IOException {

        if (secondsLimit < 5) {
            throw new IllegalArgumentException(
                    "requires at least 5 seconds to get meaningful results");
        }

        if (requestsLimit < MINIMUM_REQUESTS) {
            throw new IllegalArgumentException(
                    String.format(
                            "requires at least %d requests to get meaningful results",
                            MINIMUM_REQUESTS));
        }

        OnlineSimpleLinearRegression regression = new OnlineSimpleLinearRegression();

        int requestsLeft = requestsLimit;
        int requestsMade = 0;
        double secondsLeft = secondsLimit;
        int currentDelay = 1;

        // send requests until we're either out of time or out of requests
        while (requestsLeft > 0 && secondsLeft > 0) {

            // apply the provided function to get the dependent variable
            double y = requestSender.apply(currentDelay);

            // this is not a general assertion, but in our case, we want to stop early
            // if the expected delay isn't at LEAST as much as the requested delay
            if (y < currentDelay) {
                return false;
            }

            // update the regression computation with a new time pair
            regression.addPoint(currentDelay, y);

            // failure case if we're clearly not even close
            if (!regression.isWithinConfidence(0.3, 1.0, 0.5)) {
                return false;
            }

            // update seconds left, requests left, and increase the next delay
            secondsLeft = secondsLeft - y;
            requestsLeft = requestsLeft - 1;
            requestsMade++;
            currentDelay = currentDelay + 1;

            // if doing a longer request next would put us over time, wrap around to sending shorter
            // requests
            if (regression.predict(currentDelay) > secondsLeft) {
                currentDelay = 1;
            }
        }

        // we want the slope and correlation to both be reasonably close to 1
        // if the correlation is bad, the relationship is non-linear
        // if the slope is bad, the relationship is not positively 1:1
        return requestsMade >= MINIMUM_REQUESTS
                && regression.isWithinConfidence(correlationErrorRange, 1.0, slopeErrorRange);
    }

    @FunctionalInterface
    public interface RequestSender {
        double apply(double x) throws IOException;
    }
}
