package org.zaproxy.zap.extension.foxhound.taint;

import org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class TaintOperation implements TaintLocationProvider {

    private String operation;
    private boolean source;

    private TaintLocation location;

    private List<String> arguments;

    public TaintOperation(String operation, boolean source, TaintLocation location, List<String> arguments) {
        this.operation = operation;
        this.source = source;
        this.location = location;
        this.arguments = arguments;
    }

    public TaintOperation() {
        this.arguments = new ArrayList<>();
    }

    public String getOperation() {
        return operation;
    }

    public void setOperation(String operation) {
        this.operation = operation;
    }

    public boolean isSource() {
        return source;
    }

    public TaintSourceType getSourceType() {
        if (isSource() && FoxhoundConstants.SOURCE_NAME_TYPE_MAP.containsKey(this.operation)) {
            return FoxhoundConstants.SOURCE_NAME_TYPE_MAP.get(this.operation);
        }
        return null;
    }

    public TaintSinkType getSinkType() {
        if (isSource() && FoxhoundConstants.SINK_NAME_TYPE_MAP.containsKey(this.operation)) {
            return FoxhoundConstants.SINK_NAME_TYPE_MAP.get(this.operation);
        }
        return null;
    }

    public void setSource(boolean source) {
        this.source = source;
    }

    @Override
    public TaintLocation getLocation() {
        return location;
    }

    public void setLocation(TaintLocation location) {
        this.location = location;
    }

    public List<String> getArguments() {
        return arguments;
    }

    public void setArguments(List<String> arguments) {
        this.arguments = arguments;
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof TaintOperation that)) return false;
        return source == that.source && Objects.equals(operation, that.operation) && Objects.equals(location, that.location) && Objects.equals(arguments, that.arguments);
    }

    @Override
    public int hashCode() {
        return Objects.hash(operation, source, location, arguments);
    }

    @Override
    public String toString() {
        return "TaintOperation{" +
                "operation='" + operation + '\'' +
                ", source=" + source +
                ", location=" + location +
                ", arguments=" + arguments +
                '}';
    }
}
