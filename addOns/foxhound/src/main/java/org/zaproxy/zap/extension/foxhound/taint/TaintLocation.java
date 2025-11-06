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

    public TaintLocation(String filename, String function, int line, int pos, int scriptLine, String md5) {
        this.filename = filename;
        this.function = function;
        this.line = line;
        this.pos = pos;
        this.next_line = 0;
        this.next_pos = 0;
        this.scriptLine = scriptLine;
        this.md5 = md5;
    }

    public TaintLocation() {

    }

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


    @Override
    public boolean equals(Object object) {
        if (!(object instanceof TaintLocation location)) return false;
        return line == location.line && pos == location.pos && next_line == location.next_line && next_pos == location.next_pos && scriptLine == location.scriptLine && Objects.equals(filename, location.filename) && Objects.equals(function, location.function) && Objects.equals(md5, location.md5);
    }

    @Override
    public int hashCode() {
        return Objects.hash(filename, function, line, pos, next_line, next_pos, scriptLine, md5);
    }

    @Override
    public String toString() {
        return "TaintLocation{" +
                "filename='" + filename + '\'' +
                ", function='" + function + '\'' +
                ", line=" + line +
                ", pos=" + pos +
                ", next_line=" + next_line +
                ", next_pos=" + next_pos +
                ", scriptLine=" + scriptLine +
                ", md5='" + md5 + '\'' +
                '}';
    }
}
