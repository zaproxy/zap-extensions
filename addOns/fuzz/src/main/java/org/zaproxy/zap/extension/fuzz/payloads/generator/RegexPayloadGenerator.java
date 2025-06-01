/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.payloads.generator;

import com.github.curiousoddman.rgxgen.RgxGen;
import com.github.curiousoddman.rgxgen.iterators.StringIterator;
import com.github.curiousoddman.rgxgen.parsing.dflt.RgxGenParseException;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

/**
 * A {@code StringPayloadGenerator} that generates {@code DefaultPayload}s based on a regular
 * expression.
 *
 * @see DefaultPayload
 */
public class RegexPayloadGenerator implements StringPayloadGenerator {

    /**
     * Default limit for calculation of number of generated payloads of an infinite regular
     * expression.
     *
     * @see #calculateNumberOfPayloads(String, int)
     */
    public static final int DEFAULT_LIMIT_CALCULATION_PAYLOADS = 10000000;

    private final RgxGen generator;
    private final int maxPayloads;

    private final int numberOfPayloads;

    private final boolean randomOrder;

    public RegexPayloadGenerator(String regex) {
        this(regex, 0);
    }

    public RegexPayloadGenerator(String regex, int maxPayloads) {
        this(regex, maxPayloads, maxPayloads, false);
    }

    public RegexPayloadGenerator(String regex, int maxPayloads, boolean randomOrder) {
        this(regex, maxPayloads, maxPayloads, randomOrder);
    }

    public RegexPayloadGenerator(String regex, int maxPayloads, int limitCalculationPayloads) {
        this(regex, maxPayloads, limitCalculationPayloads, false);
    }

    public RegexPayloadGenerator(
            String regex, int maxPayloads, int limitCalculationPayloads, boolean randomOrder) {
        validateValid(regex);
        this.generator = RgxGen.parse(regex);
        this.maxPayloads = maxPayloads;
        this.numberOfPayloads =
                calculateNumberOfPayloadsImpl(generator, limitCalculationPayloads, randomOrder);
        this.randomOrder = randomOrder;
    }

    @Override
    public long getNumberOfPayloads() {
        return numberOfPayloads;
    }

    @Override
    public ResettableAutoCloseableIterator<DefaultPayload> iterator() {
        return new RegexIterator(generator, maxPayloads, randomOrder);
    }

    @Override
    public RegexPayloadGenerator copy() {
        return this;
    }

    /**
     * Tells whether or not the given {@code regex} has a valid syntax for the payload generator.
     *
     * @param regex the regular expression that will be validated
     * @return {@code true} if the {@code regex} has a valid syntax, {@code false} otherwise
     * @see #isValid(String)
     */
    public static boolean hasValidSyntax(String regex) {
        if (regex == null) {
            throw new IllegalArgumentException("Parameter regex must not be null.");
        }
        try {
            RgxGen.parse(regex);
            return true;
        } catch (RgxGenParseException e) {
            return false;
        }
    }

    /**
     * Tells whether or not the given {@code regex} is valid for the payload generator.
     *
     * <p>A regular expression might have a valid syntax but still be invalid for the payload
     * generator if it takes too much time to be processed.
     *
     * @param regex the regular expression that will be validated
     * @return {@code true} if the {@code regex} is valid, {@code false} otherwise
     * @throws IllegalArgumentException if the given {@code regex} is {@code null}
     * @see #hasValidSyntax(String)
     */
    public static boolean isValid(final String regex) {
        return hasValidSyntax(regex);
    }

    /**
     * Tells whether or not the given {@code regex} is infinite, that is, generates an infinite
     * number of payloads, taking into account the given {@code limit}.
     *
     * @param regex the regular expression that will be validated
     * @param limit if positive, the maximum number of payloads that are allowed, otherwise,
     *     negative or zero, for no limit
     * @return {@code true} if the {@code regex} is infinite, {@code false} otherwise
     * @throws IllegalArgumentException if the given {@code regex} is {@code null} or not valid
     * @see #isValid(String)
     */
    public static boolean isInfinite(String regex, int limit) {
        validateValid(regex);
        return isInfiniteImpl(RgxGen.parse(regex), limit);
    }

    private static void validateValid(String regex) {
        if (regex == null) {
            throw new IllegalArgumentException("The provided regular expression must not be null.");
        }
        if (!isValid(regex)) {
            throw new IllegalArgumentException(
                    "The provided regular expression must be valid: " + regex);
        }
    }

    private static boolean isInfiniteImpl(RgxGen generator, int limit) {
        try {
            return generator.getUniqueEstimation().isEmpty() && limit <= 0;
        } catch (StackOverflowError ignore) {
            // Infinite...
        }
        return true;
    }

    /**
     * Calculates the number of payloads that the given regular expression would produce, limiting
     * up to the given {@code limit} , if positive.
     *
     * <p>If the regular expression is infinite and no limit is provided it returns {@code
     * DEFAULT_LIMIT_CALCULATION_PAYLOADS}.
     *
     * @param regex the regular expression that will be used to calculate the number of payloads
     *     generated
     * @param limit if positive, the maximum number of payloads that are allowed, otherwise,
     *     negative or zero, for no limit
     * @return the number of payloads that would be produced by the given regular expression
     * @throws IllegalArgumentException if the given {@code regex} is {@code null} or not valid
     * @see #DEFAULT_LIMIT_CALCULATION_PAYLOADS
     * @see #calculateNumberOfPayloads(String, int, boolean)
     * @see #isInfinite(String, int)
     * @see #isValid(String)
     */
    public static int calculateNumberOfPayloads(String regex, int limit) {
        return calculateNumberOfPayloads(regex, limit, false);
    }

    /**
     * Calculates the number of payloads that the given regular expression would produce, limiting
     * up to the given {@code limit} (if positive) and whether it's random.
     *
     * <p>If the payloads should be generated in random order the limit would be the number of
     * payloads, otherwise, if the regular expression is infinite and no limit is provided it
     * returns {@code DEFAULT_LIMIT_CALCULATION_PAYLOADS}.
     *
     * @param regex the regular expression that will be used to calculate the number of payloads
     *     generated
     * @param limit if positive, the maximum number of payloads that are allowed, otherwise,
     *     negative or zero, for no limit
     * @param randomOrder {@code true} if the payloads are generated randomly, {@code false}
     *     otherwise.
     * @return the number of payloads that would be produced by the given regular expression
     * @throws IllegalArgumentException if the given {@code regex} is {@code null} or not valid
     * @see #DEFAULT_LIMIT_CALCULATION_PAYLOADS
     * @see #calculateNumberOfPayloads(String, int)
     * @see #isInfinite(String, int)
     * @see #isValid(String)
     */
    public static int calculateNumberOfPayloads(String regex, int limit, boolean randomOrder) {
        validateValid(regex);
        return calculateNumberOfPayloadsImpl(RgxGen.parse(regex), limit, randomOrder);
    }

    private static int calculateNumberOfPayloadsImpl(
            RgxGen generator, int limit, boolean randomOrder) {
        if (randomOrder) {
            return Math.max(0, limit);
        }
        var estimation = generator.getUniqueEstimation();
        if (estimation.isEmpty()) {
            if (limit > 0) {
                return limit;
            }
            return DEFAULT_LIMIT_CALCULATION_PAYLOADS;
        }

        try {
            return estimation.get().intValueExact();
        } catch (ArithmeticException e) {
            return DEFAULT_LIMIT_CALCULATION_PAYLOADS;
        }
    }

    private static class RegexIterator implements ResettableAutoCloseableIterator<DefaultPayload> {

        private final RgxGen generator;
        private final int maxPayloads;
        private final boolean randomOrder;
        private StringIterator iterator;
        private int count;

        public RegexIterator(RgxGen generator, int maxPayloads, boolean randomOrder) {
            this.generator = generator;
            this.maxPayloads = maxPayloads;
            this.randomOrder = randomOrder;
            reset();
        }

        @Override
        public boolean hasNext() {
            if (randomOrder) {
                return count < maxPayloads;
            }

            if (maxPayloads > 0 && count >= maxPayloads) {
                return false;
            }
            return iterator.hasNext();
        }

        @Override
        public DefaultPayload next() {
            count++;
            if (randomOrder) {
                return new DefaultPayload(generator.generate());
            }

            return new DefaultPayload(iterator.next());
        }

        @Override
        public void remove() {}

        @Override
        public void reset() {
            iterator = generator.iterateUnique();
            count = 0;
        }

        @Override
        public void close() {}
    }
}
