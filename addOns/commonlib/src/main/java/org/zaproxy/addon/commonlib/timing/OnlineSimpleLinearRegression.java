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

/**
 * A helper class to compute the Simple Linear Regression of a series of (x,y) pairs. This
 * particular implementation is "online", meaning you can add points to an existing computation and
 * efficiently update it with new information. This is useful for us because generally, we will want
 * to check the correlation after each request. <br>
 * <br>
 * The underlying algorithm relies on a modified version of <a
 * href="https://jonisalonen.com/2013/deriving-welfords-method-for-computing-variance/">Welford's
 * method</a>, which has comparable numerical stability to the so-called "two-pass" variance
 * computations. <br>
 * <br>
 * By convention, we fix correlation and slope at 1.0 and the intercept at 0.0 when insufficient
 * data points (<2) have been added.
 *
 * @since 1.20.0
 */
public class OnlineSimpleLinearRegression {
    private double count;
    private double independentSum;
    private double dependentSum;

    // these are not technically the variances, but variance * n, hence the name
    // you can also think of them as the sum of the residuals
    private double independentVarianceN;
    private double dependentVarianceN;
    private double sampleCovarianceN;

    private double slope = 1;
    private double intercept;
    private double correlation = 1;

    OnlineSimpleLinearRegression() {}

    /**
     * Add a single data point to the linear regression computation and update internal slope and
     * correlation. O(1) in time and space.
     *
     * @param x the independent input variable
     * @param y the dependent output corresponding to the input x
     */
    public void addPoint(double x, double y) {
        // based on the new values but the old mean for Welford's method
        double independentResidualAdjustment = x - independentSum / count;
        double dependentResidualAdjustment = y - dependentSum / count;

        count += 1;
        independentSum += x;
        dependentSum += y;

        // avoid doing NaN stuff if we don't have enough data yet
        if (Double.isNaN(independentResidualAdjustment)) {
            return;
        }

        double independentResidual = x - independentSum / count;
        double dependentResidual = y - dependentSum / count;

        // modified version of Welford's method
        independentVarianceN += independentResidual * independentResidualAdjustment;
        dependentVarianceN += dependentResidual * dependentResidualAdjustment;
        sampleCovarianceN += independentResidual * dependentResidualAdjustment;

        // the extra N's cancel in both of these computations
        slope = sampleCovarianceN / independentVarianceN;
        correlation = slope * Math.sqrt(independentVarianceN / dependentVarianceN);
        correlation *= correlation;

        // derive intercept from slope
        intercept = independentSum / count - (dependentSum / count) * slope;

        // one last correction: if the line in question is FLAT (albeit unrealistic), correlation
        // will NaN. technically though, that means it's a line, so we should set this
        if (Double.isNaN(correlation)) {
            correlation = 1;
        }
    }

    public double getSlope() {
        return slope;
    }

    public double getIntercept() {
        return intercept;
    }

    public double getCorrelation() {
        return correlation;
    }

    /**
     * Uses the current regression to predict an output from an input. Note that depending on how
     * much data you've given this regression, and how much the data actually correlates, this
     * estimate could be infinitely incorrect. Ensure high correlation if the accuracy of this
     * estimate is going to matter.
     *
     * @param x the independent variable
     * @return the expected dependent value
     */
    public double predict(double x) {
        return slope * x + intercept;
    }

    /**
     * Verifies that the correlation and slope are within user-defined error ranges.
     *
     * @param correlationErrorRange the acceptance interval (0.0-1.0) for correlation
     * @param expectedSlope the expected slope value (typically 1.0)
     * @param slopeErrorRange the acceptance interval for slope
     * @return true, if both the correlation and slope are within acceptable error ranges.
     */
    public boolean isWithinConfidence(
            double correlationErrorRange, double expectedSlope, double slopeErrorRange) {
        return correlation > 1.0 - correlationErrorRange
                && Math.abs(expectedSlope - slope) < slopeErrorRange;
    }
}
