package org.zaproxy.zap.extension.aem.yaml;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RequestYAML {

	private HttpMethodEnumYAML method = HttpMethodEnumYAML.GET;

	private List<String> paths = new ArrayList<>();

	private String query;

	private String fragment;

	private boolean follow = false;

	private boolean firstMatch = false;

	private Map<String, String> headers = new HashMap<>();

	public HttpMethodEnumYAML getMethod() {
		return method;
	}

	public void setMethod(HttpMethodEnumYAML method) {
		this.method = method;
	}

	public List<String> getPaths() {
		return paths;
	}

	public void setPaths(List<String> paths) {
		this.paths = paths;
	}

	public boolean isFollow() {
		return follow;
	}

	public void setFollow(boolean follow) {
		this.follow = follow;
	}

	public String getQuery() {
		return query;
	}

	public void setQuery(String query) {
		this.query = query;
	}

	public String getFragment() {
		return fragment;
	}

	public void setFragment(String fragment) {
		this.fragment = fragment;
	}

	public Map<String, String> getHeaders() {
		return headers;
	}

	public void setHeaders(Map<String, String> headers) {
		this.headers = headers;
	}

	public boolean isFirstMatch() {
		return firstMatch;
	}

	public void setFirstMatch(boolean firstMatch) {
		this.firstMatch = firstMatch;
	}

}
