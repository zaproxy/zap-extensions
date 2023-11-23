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

import static org.hamcrest.MatcherAssert.assertThat;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;

/** Unit test for {@link OnlineSimpleLinearRegression}. */
class OnlineSimpleLinearRegressionUnitTest {

    @Test
    // in a naive implementation that is not as numerically stable,
    // these inputs will cause catastrophic cancellation
    void verifyNumericalStability() {
        // Given
        double[][] variables = {
            {1, 1}, {2, 2}, {3, 3}, {4, 4}, {5, 5}, {1, 1}, {2, 2}, {2, 2}, {2, 2}
        };
        double slope = 1;
        double corr = 1;
        // When
        OnlineSimpleLinearRegression regression = new OnlineSimpleLinearRegression();
        for (double[] vars : variables) regression.addPoint(vars[0], vars[1]);
        // Then
        assertThat(regression.getSlope(), Matchers.closeTo(slope, 1e-8));
        assertThat(regression.getCorrelation(), Matchers.closeTo(corr, 1e-8));
    }

    @Test
    // if given two points, should reduce to the linear case
    void verifyExactLinearRegression() {
        // Given
        double[][] variables = {{1, 1}, {2, 3}};
        double slope = 2;
        double corr = 1;
        // When
        OnlineSimpleLinearRegression regression = new OnlineSimpleLinearRegression();
        for (double[] vars : variables) regression.addPoint(vars[0], vars[1]);
        // Then
        assertThat(regression.getSlope(), Matchers.closeTo(slope, 1e-8));
        assertThat(regression.getCorrelation(), Matchers.closeTo(corr, 1e-8));
    }

    @Test
    // can we verify an externally computed linear regression?
    void verifyKnownLinearRegression() {
        // Given
        // these numbers were double-checked in...Microsoft Excel, so its rock solid
        double[][] variables = {
            {1, 1.348520581}, {2, 2.524046187}, {3, 3.276944688}, {4, 4.735374498}, {5, 5.150291657}
        };
        double slope = 0.981487046;
        double corr = 0.979228906;
        // When
        OnlineSimpleLinearRegression regression = new OnlineSimpleLinearRegression();
        for (double[] vars : variables) regression.addPoint(vars[0], vars[1]);
        // Then
        assertThat(regression.getSlope(), Matchers.closeTo(slope, 1e-8));
        assertThat(regression.getCorrelation(), Matchers.closeTo(corr, 1e-8));
    }

    @Test
    // does a nonlinear function result in low correlation?
    void verifyLowCorrelationWithNonLinear() {
        // Given
        double[][] variables = {{1, 2}, {2, 4}, {3, 8}, {4, 16}, {5, 32}};
        // When
        OnlineSimpleLinearRegression regression = new OnlineSimpleLinearRegression();
        for (double[] vars : variables) regression.addPoint(vars[0], vars[1]);
        // Then
        assertThat(regression.getCorrelation(), Matchers.lessThan(0.9));
    }
}
