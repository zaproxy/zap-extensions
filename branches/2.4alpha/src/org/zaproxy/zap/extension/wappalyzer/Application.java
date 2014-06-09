package org.zaproxy.zap.extension.wappalyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.swing.ImageIcon;

public class Application {

	private String name;
	private String website;
	private ImageIcon icon = null;
	private List<String> categories = new ArrayList<String>();
	private List<Map<String, AppPattern>> headers;
	private List<AppPattern> url = new ArrayList<AppPattern>();
	private List<AppPattern> html = new ArrayList<AppPattern>();
	// TODO handle meta structures 
	private List<AppPattern> script = new ArrayList<AppPattern>();

	private List<String> implies = new ArrayList<String>();

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getWebsite() {
		return website;
	}

	public void setWebsite(String website) {
		this.website = website;
	}

	public List<String> getCategories() {
		return categories;
	}

	public void setCategories(List<String> categories) {
		this.categories = categories;
	}

	public void setHeaders(List<Map<String, AppPattern>> headers) {
		this.headers = headers;
	}

	public void setUrl(List<AppPattern> url) {
		this.url = url;
	}

	public void setHtml(List<AppPattern> html) {
		this.html = html;
	}

	public void setScript(List<AppPattern> script) {
		this.script = script;
	}

	public void setImplies(List<String> implies) {
		this.implies = implies;
	}

	public void addCategories(String category) {
		this.categories.add(category);
	}

	public List<Map<String, AppPattern>> getHeaders() {
		return headers;
	}

	public void addHeaders(Map<String, AppPattern> header) {
		this.headers.add(header);
	}

	public List<AppPattern> getUrl() {
		return url;
	}

	public void addUrl(AppPattern u) {
		this.url.add(u);
	}

	public List<AppPattern> getHtml() {
		return html;
	}

	public void addHtml(AppPattern h) {
		this.html.add(h);
	}

	public List<AppPattern> getScript() {
		return script;
	}

	public void addScript(AppPattern s) {
		this.script.add(s);
	}

	public List<String> getImplies() {
		return implies;
	}

	public void addImplies(String i) {
		this.implies.add(i);
	}

	public ImageIcon getIcon() {
		return icon;
	}

	public void setIcon(ImageIcon icon) {
		this.icon = icon;
	}

	// TODO global js variables - cant use?
	//private Pattern env;
	
	
	

}
