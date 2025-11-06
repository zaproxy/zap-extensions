package org.zaproxy.zap.extension.foxhound.taint;

import java.util.Objects;

public class Range {

    protected int begin;
    protected int end;

    public Range() {
        this.begin = 0;
        this.end = 0;
    }

    public Range(int begin, int end) {
        this.begin = begin;
        this.end = end;
    }

    public int getBegin() {
        return begin;
    }

    public void setBegin(int begin) {
        this.begin = begin;
    }

    public int getEnd() {
        return end;
    }

    public void setEnd(int end) {
        this.end = end;
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof Range range)) return false;
        return begin == range.begin && end == range.end;
    }

    @Override
    public int hashCode() {
        return Objects.hash(begin, end);
    }
}
