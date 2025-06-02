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
package org.zaproxy.addon.commonlib.timing;

import java.io.IOException;

/**
 * Utility class to host time-based blind detection algorithms.
 *
 * @since 1.20.0
 */
public class TimingUtils {

    // Minimum requests required for a result
    private static final int MINIMUM_REQUESTS = 2;

    /**
     * Sends time-based blind requests and analyze the response times using simple linear
     * regression. If this returns true, then an increment in payload delay positively correlates to
     * an increment in actual delay, indicating the presence of an injection vulnerability. This
     * particular implementation is designed to send as few requests as possible, and will return
     * false immediately if the correlation dips too low or if the actual delay is less than the
     * expected delay. This implementation also requires a minimum number of request data points to
     * prevent false positives where a website only responded once or twice within the time limit.
     *
     * <p>This implementation uses a series of alternating high delay and low delay requests to
     * minimize the possibility of false positives from normal variations in application response
     * time. For example, if it tested a delay of 1 second and 2 seconds, there's a very real
     * possibility that the application response times normally vary by 1 second and we get a false
     * positive. Whereas if it tests 15 seconds and 1 second, there is a much smaller chance that
     * the application response times normally vary by 14 seconds.
     *
     * @param requestsLimit the hard limit on how many times at most requestSender will be called.
     *     In practice, the number of requests will usually be much less, because if a positive is
     *     clearly not even close, we exit early. Note that 1 more request than the limit may be
     *     sent because the test actually makes pairs of requests (one high sleep value and one low
     *     sleep value)
     * @param highSleepTimeSeconds the high sleep value to send in requests
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
            int highSleepTimeSeconds,
            RequestSender requestSender,
            double correlationErrorRange,
            double slopeErrorRange)
            throws IOException {

        if (requestsLimit < MINIMUM_REQUESTS) {
            throw new IllegalArgumentException(
                    String.format(
                            "requires at least %d requests to get results", MINIMUM_REQUESTS));
        }

        OnlineSimpleLinearRegression regression = new OnlineSimpleLinearRegression();

        int requestsLeft = requestsLimit;

        // send requests until we've hit the max requests
        // requests are sent in pairs - one high sleep value and one low sleep value
        // optimized to stop early if correlation is clearly not possible
        while (requestsLeft > 0) {
            // send the high sleep value request
            boolean isCorrelationPossible =
                    sendRequestAndTestConfidence(regression, requestSender, highSleepTimeSeconds);
            // return early if we're clearly not close
            if (!isCorrelationPossible) {
                return false;
            }

            // send the low value sleep request
            isCorrelationPossible = sendRequestAndTestConfidence(regression, requestSender, 1);
            // return early if we're clearly not close
            if (!isCorrelationPossible) {
                return false;
            }

            // update requests left
            requestsLeft = requestsLeft - 2;
        }

        // we want the slope and correlation to both be reasonably close to 1
        // if the correlation is bad, the relationship is non-linear
        // if the slope is bad, the relationship is not positively 1:1
        return regression.isWithinConfidence(correlationErrorRange, 1.0, slopeErrorRange);
    }

    /**
     * Helper function to send a single request and add it to the regression Also has optimizations
     * to check if the a correlation is clearly not possible
     *
     * @return - true if a correlation is still possible, false if a correlation is clearly not
     *     possible
     */
    private static boolean sendRequestAndTestConfidence(
            OnlineSimpleLinearRegression regression, RequestSender requestSender, int delay)
            throws IOException {
        // apply the provided function to get the dependent variable
        double y = requestSender.apply(delay);

        // this is not a general assertion, but in our case, we want to stop early
        // if the expected delay isn't at LEAST as much as the requested delay
        if (y < delay) {
            return false;
        }

        // update the regression computation with a new time pair
        regression.addPoint(delay, y);

        // failure case if we're clearly not even close
        if (!regression.isWithinConfidence(0.3, 1.0, 0.5)) {
            return false;
        }

        return true;
    }

    @FunctionalInterface
    public interface RequestSender {
        double apply(double x) throws IOException;
    }
}
