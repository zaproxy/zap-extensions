package org.zaproxy.zap.extension.foxhound.taint;

import org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public interface SourceSinkProvider {

    abstract public Set<TaintOperation> getSources();
    abstract public TaintOperation getSink();



}
