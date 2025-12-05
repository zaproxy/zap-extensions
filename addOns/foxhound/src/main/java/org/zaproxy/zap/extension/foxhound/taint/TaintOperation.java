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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants;

public class TaintOperation implements TaintLocationProvider {

    private String operation;
    private boolean source;

    private TaintLocation location;

    private List<String> arguments;

    public TaintOperation(
            String operation, boolean source, TaintLocation location, List<String> arguments) {
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
        return source == that.source
                && Objects.equals(operation, that.operation)
                && Objects.equals(location, that.location)
                && Objects.equals(arguments, that.arguments);
    }

    @Override
    public int hashCode() {
        return Objects.hash(operation, source, location, arguments);
    }

    @Override
    public String toString() {
        return "TaintOperation{"
                + "operation='"
                + operation
                + '\''
                + ", source="
                + source
                + ", location="
                + location
                + ", arguments="
                + arguments
                + '}';
    }
}
