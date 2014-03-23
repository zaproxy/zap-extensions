package org.zaproxy.zap.extension.jruby;

import java.io.IOException;

import javax.script.ScriptException;

import org.zaproxy.zap.extension.script.ScriptWrapper;

public class JrubyScriptWrapper extends ScriptWrapper {
	
	@SuppressWarnings("unchecked")
	public <T> T getInterface(Class<T> class1) throws ScriptException, IOException {
		// JRuby is a pain and doesnt seem to work like other JSR223 languages
		return (T)this.getEngine().getEngine().eval(this.getContents());
	}

}
