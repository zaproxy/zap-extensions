package org.zaproxy.zap.extension.wappalyzer;

import org.zaproxy.zap.utils.Stats;

import com.google.re2j.Pattern;

public class AppPattern {

	private Pattern re2jPattern = null;
	private java.util.regex.Pattern javaPattern = null;
	private String version = null;
	private int confidence = 100;
	private boolean compareRej2AndJava = false;
	
	public void setPattern(String pattern) {
		this.javaPattern = java.util.regex.Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
		try {
			// This takes precedence, if it compiles
			this.re2jPattern = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
		} catch (com.google.re2j.PatternSyntaxException e) {
			// Ignore
		}
	}
	/**
	 * Returns the java version of the regex pattern - its provided as the core requires a java Pattern when searching
	 * for evidence.
	 * It should not be used for matching in this package, use findInString instead for performance reasons.
	 * @return
	 */
	public java.util.regex.Pattern getJavaPattern() {
		return javaPattern;
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
	public boolean findInString(String str) {
		if (this.compareRej2AndJava) {
			return this.findInStringCompareVersion(str);
		} else {
			if (this.re2jPattern != null) {
				return this.re2jPattern.matcher(str).find();
			} else {
				return this.javaPattern.matcher(str).find();
			}
		}
	}
	private boolean findInStringCompareVersion(String str) {
		if (this.re2jPattern != null) {
			long start = System.currentTimeMillis();
			boolean r = this.re2jPattern.matcher(str).find();
			Stats.incCounter("stats.wappalyser.time_re2j", System.currentTimeMillis()- start);
			Stats.incCounter("stats.wappalyser.pattern." + this.javaPattern.toString(), System.currentTimeMillis()- start);
			start = System.currentTimeMillis();
			boolean j = this.javaPattern.matcher(str).find();
			Stats.incCounter("stats.wappalyser.time_java", System.currentTimeMillis()- start);
			if (r == j) {
				Stats.incCounter("stats.wappalyser.same");
			} else if (r) {
				Stats.incCounter("stats.wappalyser.justr");
			} else {
				Stats.incCounter("stats.wappalyser.justj");
			}
			return r;
		} else {
			Stats.incCounter("stats.wappalyser.no_r_pattern");
			return this.javaPattern.matcher(str).find();
		}
	}
	/**
	 * Only set this if you want to compare the java and RE2J Pattern implementations and/or how long
	 * each of the individual regexs take to run. It will cause the rules to run significantly slower.
	 * @param compareRej2AndJava
	 */
	protected void setCompareRej2AndJava(boolean compareRej2AndJava) {
		this.compareRej2AndJava = compareRej2AndJava;
	}
}
