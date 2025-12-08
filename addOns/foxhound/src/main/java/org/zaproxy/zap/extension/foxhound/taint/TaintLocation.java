/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.foxhound.taint;

import java.util.Objects;

public class TaintLocation {

    private String filename;
    private String function;
    private int line;
    private int pos;
    private int next_line;
    private int next_pos;

    private int scriptLine;
    private String md5;

    public TaintLocation(
            String filename, String function, int line, int pos, int scriptLine, String md5) {
        this.filename = filename;
        this.function = function;
        this.line = line;
        this.pos = pos;
        this.next_line = 0;
        this.next_pos = 0;
        this.scriptLine = scriptLine;
        this.md5 = md5;
    }

    public TaintLocation() {}

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public String getFunction() {
        return function;
    }

    public void setFunction(String function) {
        this.function = function;
    }

    public int getLine() {
        return line;
    }

    public void setLine(int line) {
        this.line = line;
    }

    public int getPos() {
        return pos;
    }

    public void setPos(int pos) {
        this.pos = pos;
    }

    public int getNextLine() {
        return next_line;
    }

    public void setNextLine(int next_line) {
        this.next_line = next_line;
    }

    public int getNextPos() {
        return next_pos;
    }

    public void setNextPos(int next_pos) {
        this.next_pos = next_pos;
    }

    public int getScriptLine() {
        return scriptLine;
    }

    public void setScriptLine(int scriptLine) {
        this.scriptLine = scriptLine;
    }

    public String getMd5() {
        return md5;
    }

    public void setMd5(String md5) {
        this.md5 = md5;
    }

    private static int ordinalIndexOf(String str, String substr, int n) {
        int pos = str.indexOf(substr);
        while (--n > 0 && pos != -1) pos = str.indexOf(substr, pos + 1); // pos is one-origin number
        return pos;
    }

    private static int getStringIndexFromLineAndPosition(String s, int line, int pos) {
        return ordinalIndexOf(s, "\n", line - 1) + pos;
    }

    // Computes the index range
    public Range getCodeSpan(String s) {
        int start = getStringIndexFromLineAndPosition(s, getLine(), getPos());
        int end = getStringIndexFromLineAndPosition(s, getNextLine(), getNextPos());
        if (start > end) {
            int temp;
            temp = start;
            start = end;
            end = temp;
        }
        return new Range(start, end);
    }

    public String getCodeForEvidence(String s) {
        if ((s == null || s.isEmpty())) {
            return "";
        }
        Range range = getCodeSpan(s);
        return s.substring(range.getBegin(), range.getEnd());
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof TaintLocation location)) return false;
        return line == location.line
                && pos == location.pos
                && next_line == location.next_line
                && next_pos == location.next_pos
                && scriptLine == location.scriptLine
                && Objects.equals(filename, location.filename)
                && Objects.equals(function, location.function)
                && Objects.equals(md5, location.md5);
    }

    @Override
    public int hashCode() {
        return Objects.hash(filename, function, line, pos, next_line, next_pos, scriptLine, md5);
    }

    public String getViewSource() {
        return "view-source:" + filename + "#line" + line;
    }

    @Override
    public String toString() {
        return filename + ':' + line + ':' + pos;
    }
}
