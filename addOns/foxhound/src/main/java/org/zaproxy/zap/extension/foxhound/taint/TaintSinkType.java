package org.zaproxy.zap.extension.foxhound.taint;

public class TaintSinkType extends NamedAndTagged<TaintSinkType.SinkTag> {

    public enum SinkTag {
        HTML,
        JAVASCRIPT,
        CSS,
        NETWORK,
        POSTMESSAGE,
        SRC,
        STORAGE,
        XSS,
        XSRF,
        FETCH,
        XHR,
        LOCATION,
        URL
    }

    public TaintSinkType(String name) {
        super(name);
    }

}
