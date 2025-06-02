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
package org.zaproxy.zap.extension.fuzz.messagelocations;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.model.InvalidMessageException;

public class MultipleMessageLocationsBreadthFirstReplacer<T extends Message>
        implements MultipleMessageLocationsReplacer<T> {

    private static final Logger LOGGER =
            LogManager.getLogger(MultipleMessageLocationsBreadthFirstReplacer.class);

    private MessageLocationReplacer<T> replacer;
    private List<MessageLocationReplacementGenerator<?, ?>> replacementGenerators;

    private SortedSet<MessageLocationReplacement<?>> currentReplacements;
    private MessageLocationReplacement<?>[] listCurrentReplacements;

    private boolean initialised;
    private boolean setup;

    private int tailIndex;
    private MessageLocationReplacementGenerator<?, ?> tail;

    private long numberOfReplacements;

    @Override
    public boolean isInitialised() {
        return initialised;
    }

    @Override
    public void init(
            MessageLocationReplacer<T> replacer,
            SortedSet<? extends MessageLocationReplacementGenerator<?, ?>>
                    messageLocationReplacementGenerator) {
        this.replacer = replacer;

        currentReplacements = new TreeSet<>();
        listCurrentReplacements =
                new MessageLocationReplacement<?>[messageLocationReplacementGenerator.size()];

        replacementGenerators = new ArrayList<>(messageLocationReplacementGenerator.size());
        for (MessageLocationReplacementGenerator<?, ?> mlr : messageLocationReplacementGenerator) {
            if (mlr.hasNext()) {
                long replacements = mlr.getNumberOfReplacements();
                if (replacements
                        != MessageLocationReplacementGenerator.UNKNOWN_NUMBER_OF_REPLACEMENTS) {
                    numberOfReplacements *= replacements;
                }
                replacementGenerators.add(mlr);
            }
        }
        numberOfReplacements = 0;

        tailIndex = replacementGenerators.size() - 1;
        tail = replacementGenerators.get(tailIndex);
        initialised = true;
        setup = true;
    }

    @Override
    public long getNumberOfReplacements() {
        return numberOfReplacements;
    }

    @Override
    public boolean hasNext() {
        for (int i = tailIndex; i >= 0; i--) {
            if (replacementGenerators.get(i).hasNext()) {
                return true;
            }
        }
        return false;
    }

    @Override
    public T next() throws InvalidMessageException {
        if (setup) {
            setup();
            setup = false;
        }

        if (!tail.hasNext()) {
            tail.reset();

            for (int i = tailIndex - 1; i >= 0; i--) {
                if (replacementGenerators.get(i).hasNext()) {
                    listCurrentReplacements[i] = replacementGenerators.get(i).next();
                    break;
                }

                replacementGenerators.get(i).reset();
                listCurrentReplacements[i] = replacementGenerators.get(i).next();
            }
        }

        listCurrentReplacements[tailIndex] = tail.next();

        currentReplacements.clear();
        currentReplacements.addAll(Arrays.asList(listCurrentReplacements));

        return replacer.replace(currentReplacements);
    }

    private void setup() {
        for (int i = 0; i < tailIndex; i++) {
            if (replacementGenerators.get(i).hasNext()) {
                listCurrentReplacements[i] = replacementGenerators.get(i).next();
            }
        }
    }

    @Override
    public SortedSet<MessageLocationReplacement<?>> currentReplacements() {
        return currentReplacements;
    }

    @Override
    public void close() {
        for (MessageLocationReplacementGenerator<?, ?> generator : replacementGenerators) {
            try {
                generator.close();
            } catch (Exception e) {
                LOGGER.debug("Failed to close the replacement generator:", e);
            }
        }
    }
}
