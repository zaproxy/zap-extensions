package org.zaproxy.zap.extension.foxhound.taint;

import org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants;

import javax.xml.transform.Source;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class SourceSinkUtils {

    public static Set<SourceTag> getSourceTags(SourceSinkProvider ss) {
        Set<SourceTag> tags = new HashSet<>();
        for (SourceTag t : SourceTag.values()) {
            Set<String> tagNames = FoxhoundConstants.getSourceNamesWithTag(t);
            if (!Collections.disjoint(ss.getSources(), tagNames)) {
                tags.add(t);
            }
        }
        return tags;
    }

    public static String getOperationNameList(Collection<TaintOperation> ops) {
        return String.join(", ", ops.stream().map(TaintOperation::getOperation).toList());
    }

    public static String getSourceSinkLabel(SourceSinkProvider ss) {
        return getOperationNameList(ss.getSources()) + " \u2192 " + ss.getSink().getOperation();
    }

}
