package org.zaproxy.zap.extension.foxhound.taint;

import java.util.Objects;

public class TaintLocation {

    private String filename;
    private String function;
    private int line;
    private int pos;
    private int scriptLine;
    private String md5;

    public TaintLocation(String filename, String function, int line, int pos, int scriptLine, String md5) {
        this.filename = filename;
        this.function = function;
        this.line = line;
        this.pos = pos;
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
        if (!(object instanceof TaintLocation that)) return false;
        return line == that.line && pos == that.pos && scriptLine == that.scriptLine && Objects.equals(filename, that.filename) && Objects.equals(function, that.function) && Objects.equals(md5, that.md5);
    }

    @Override
    public int hashCode() {
        return Objects.hash(filename, function, line, pos, scriptLine, md5);
    }

    @Override
    public String toString() {
        return "TaintLocation{" +
                "filename='" + filename + '\'' +
                ", function='" + function + '\'' +
                ", line=" + line +
                ", pos=" + pos +
                ", scriptLine=" + scriptLine +
                ", md5='" + md5 + '\'' +
                '}';
    }
}
