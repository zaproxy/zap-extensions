/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.backslashpoweredscanner;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;

public class Probe {
    public static byte APPEND = 0;
    public static byte PREPEND = 1;
    public static byte REPLACE = 2;

    private String name;

    private ArrayList<String> breakStrings = new ArrayList<>();
    private ArrayList<String[]> escapeStrings = new ArrayList<>();
    private byte prefix = APPEND;
    private boolean randomAnchor = true;
    private boolean useCacheBuster = false;
    private int nextBreak = -1;
    private int nextEscape = -1;

    public boolean getRequireConsistentEvidence() {
        return requireConsistentEvidence;
    }

    private boolean requireConsistentEvidence = false;

    public boolean useCacheBuster() {
        return useCacheBuster;
    }

    public Probe(String name, String... breakStrings) {
        this.name = name;
        this.breakStrings = new ArrayList<>(Arrays.asList(breakStrings));
    }

    public byte getPrefix() {
        return prefix;
    }

    public void setPrefix(byte prefix) {
        this.prefix = prefix;
    }

    public boolean getRandomAnchor() {
        return randomAnchor;
    }

    public void setRandomAnchor(boolean randomAnchor) {
        this.randomAnchor = randomAnchor;
        useCacheBuster = !randomAnchor;
    }

    public void setUseCacheBuster(boolean useCacheBuster) {
        this.useCacheBuster = useCacheBuster;
    }

    public void setEscapeStrings(String... args) {
        for (String arg : args) {
            escapeStrings.add(new String[] {arg});
        }
    }

    // args is a list of alternatives
    public void addEscapePair(String... args) {
        escapeStrings.add(args);
    }

    public String getNextBreak() {
        nextBreak++;
        return breakStrings.get(nextBreak % breakStrings.size());
    }

    public String[] getNextEscapeSet() {
        nextEscape++;
        return escapeStrings.get(nextEscape % escapeStrings.size());
    }

    public String getName() {
        return name;
    }

    static class ProbeResults {
        public HashSet<String> interesting = new HashSet<>();
        public HashSet<String> boring = new HashSet<>();
    }
}
