package org.zaproxy.zap.extension.wappalyzer;

import java.util.regex.Pattern;

public class AppPattern {

	private Pattern pattern = null;
	private String version = null;
	private int confidence = 100;
	
	public Pattern getPattern() {
		return pattern;
	}
	public void setPattern(Pattern pattern) {
		this.pattern = pattern;
	}
	public String getVersion() {
		return version;
	}
	public void setVersion(String version) {
		this.version = version;
	}
	public int getConfidence() {
		return confidence;
	}
	public void setConfidence(int confidence) {
		this.confidence = confidence;
	}
}
