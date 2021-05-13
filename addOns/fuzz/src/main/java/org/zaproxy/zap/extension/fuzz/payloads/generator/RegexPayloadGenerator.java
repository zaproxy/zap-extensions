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

import com.mifmif.common.regex.Generex;
import com.mifmif.common.regex.util.Iterator;
import dk.brics.automaton.Automaton;
import java.lang.reflect.Field;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

/**
 * A {@code StringPayloadGenerator} that generates {@code DefaultPayload}s based on a regular
 * expression.
 *
 * @see DefaultPayload
 */
public class RegexPayloadGenerator implements StringPayloadGenerator {

    private static final Logger logger = LogManager.getLogger(RegexPayloadGenerator.class);

    /**
     * Default limit for calculation of number of generated payloads of an infinite regular
     * expression.
     *
     * @see #calculateNumberOfPayloads(String, int)
     */
    public static final int DEFAULT_LIMIT_CALCULATION_PAYLOADS = 10000000;

    /**
     * The seconds that a regular expression, at most, can take to be validated.
     *
     * <p>Some regular expressions might be infinite or take too much time to be parsed, to prevent
     * hanging the running process the validation is interrupted after the given time and the
     * regular expression is considered invalid.
     */
    private static final int VALID_REGEX_MAX_SECONDS = 5;

    private static Field generexAutomatonField;

    static {
        try {
            generexAutomatonField = Generex.class.getDeclaredField("automaton");
            generexAutomatonField.setAccessible(true);
        } catch (Exception e) {
            logger.error("Failed to set Generex's automaton accessible.", e);
        }
    }

    private final Generex generator;
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
        this.generator = new Generex(regex);
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
        return Generex.isValidPattern(regex);
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
        if (!hasValidSyntax(regex)) {
            return false;
        }
        return TimeOutRunner.run(
                () -> new Generex(regex), VALID_REGEX_MAX_SECONDS, TimeUnit.SECONDS);
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
        return isInfiniteImpl(new Generex(regex), limit);
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

    private static boolean isInfiniteImpl(Generex generator, int limit) {
        try {
            return generator.isInfinite() && limit <= 0;
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
        return calculateNumberOfPayloadsImpl(new Generex(regex), limit, randomOrder);
    }

    private static int calculateNumberOfPayloadsImpl(
            Generex generator, int limit, boolean randomOrder) {
        if (randomOrder) {
            return Math.max(0, limit);
        }

        int max = limit;
        if (max <= 0 || max == DEFAULT_LIMIT_CALCULATION_PAYLOADS) {
            if (isInfiniteImpl(generator, 0)) {
                return DEFAULT_LIMIT_CALCULATION_PAYLOADS;
            }
            if (max <= 0) {
                max = Integer.MAX_VALUE;
            }
        }

        Automaton automaton = getAutomaton(generator);
        if (automaton == null) {
            // Shouldn't happen.
            return max;
        }

        return new StateStringCounter(automaton.getInitialState(), max).count();
    }

    private static Automaton getAutomaton(Generex generex) {
        if (generexAutomatonField == null) {
            return null;
        }
        try {
            return (Automaton) generexAutomatonField.get(generex);
        } catch (Exception e) {
            logger.warn("Failed to get automaton.", e);
        }
        return null;
    }

    private static class RegexIterator implements ResettableAutoCloseableIterator<DefaultPayload> {

        private final Generex generex;
        private final int maxPayloads;
        private final boolean randomOrder;
        private Iterator iterator;
        private int count;

        public RegexIterator(Generex generex, int maxPayloads, boolean randomOrder) {
            this.generex = generex;
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
                return new DefaultPayload(generex.random());
            }

            return new DefaultPayload(iterator.next());
        }

        @Override
        public void remove() {}

        @Override
        public void reset() {
            iterator = generex.iterator();
            count = 0;
        }

        @Override
        public void close() {}
    }

    /**
     * Class that runs a {@code Runnable}, stopping it if it doesn't finish after a given amount of
     * time.
     */
    private static class TimeOutRunner {

        @SuppressWarnings("deprecation")
        public static boolean run(Runnable runnable, int time, TimeUnit timeUnit) {
            final Thread thread = new Thread(runnable);
            ExecutorService executor = null;
            try {
                executor = Executors.newSingleThreadExecutor();
                Future<?> future =
                        executor.submit(
                                () -> {
                                    synchronized (thread) {
                                        thread.start();
                                        try {
                                            thread.wait();
                                        } catch (InterruptedException e) {
                                        }
                                    }
                                });

                future.get(time, timeUnit);
                return true;
            } catch (Exception e) {
                // No luck...
            } finally {
                // Stop it...
                thread.stop();
                if (executor != null) {
                    executor.shutdownNow();
                }
            }
            return false;
        }
    }
}
