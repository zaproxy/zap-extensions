/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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

import dk.brics.automaton.State;
import dk.brics.automaton.Transition;
import java.util.ArrayDeque;
import java.util.Deque;

class StateStringCounter {

    private final Deque<Step> steps;
    private boolean found;
    private int count;
    private int limit;

    public StateStringCounter(State initialState, int limit) {
        steps = new ArrayDeque<>();
        if (initialState.isAccept() && initialState.getTransitions().isEmpty()) {
            found = true;
        } else {
            steps.push(new Step(initialState));
        }
        this.limit = limit;
    }

    private boolean hasNext() {
        if (found) {
            return true;
        }
        if (steps.isEmpty()) {
            return false;
        }
        nextImpl();
        return found;
    }

    private void nextImpl() {
        Step currentStep;

        while (!steps.isEmpty() && !found) {
            currentStep = steps.pop();
            found = currentStep.build(steps);
        }
    }

    public int count() {
        while (hasNext() && count < limit) {
            if (!found) {
                nextImpl();
            }
            count++;
            found = false;
        }
        return count;
    }

    private static class Step {

        private java.util.Iterator<Transition> iteratorTransitions;
        private Transition currentTransition;
        private char currentChar;

        public Step(State state) {
            this.iteratorTransitions = state.getTransitions().iterator();
        }

        public boolean build(Deque<Step> steps) {
            if (hasCurrentTransition()) {
                currentChar++;
            } else if (!moveToNextTransition()) {
                return false;
            }

            if (currentChar <= currentTransition.getMax()) {
                if (currentTransition.getDest().isAccept()) {
                    pushForDestinationOfCurrentTransition(steps);
                    if (currentChar >= currentTransition.getMax()) {
                        currentTransition = null;
                    }
                    return true;
                }
                pushForDestinationOfCurrentTransition(steps);
                return false;
            }
            steps.push(this);
            currentTransition = null;
            return false;
        }

        private boolean hasCurrentTransition() {
            return currentTransition != null;
        }

        private boolean moveToNextTransition() {
            if (!iteratorTransitions.hasNext()) {
                return false;
            }
            currentTransition = iteratorTransitions.next();
            currentChar = currentTransition.getMin();
            return true;
        }

        private void pushForDestinationOfCurrentTransition(Deque<Step> steps) {
            steps.push(this);
            steps.push(new Step(currentTransition.getDest()));
        }
    }
}
