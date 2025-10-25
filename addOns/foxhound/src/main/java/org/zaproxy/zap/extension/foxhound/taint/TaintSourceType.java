package org.zaproxy.zap.extension.foxhound.taint;

public class TaintSourceType extends NamedAndTagged<TaintSourceType.SourceTag> {

    public static enum SourceTag {
        URL,
        STORAGE,
        MESSAGE,
        NETWORK,
        INPUT,
        DOM
    }

    public TaintSourceType(String name) {
        super(name);
    }

}
