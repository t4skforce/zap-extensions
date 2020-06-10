package org.zaproxy.zap.extension.aem.yaml;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang.StringUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Element;
import org.zaproxy.zap.extension.aem.util.JsonUtil;
import org.zaproxy.zap.network.HttpResponseBody;

public class ResponseBodyYAML {

	private String string;

	private String stringIgnoreCase;

	private String regex;

	private String css;

	private String json;

	public String getString() {
		return string;
	}

	public void setString(String string) {
		this.string = string;
	}

	public String getStringIgnoreCase() {
		return stringIgnoreCase;
	}

	public void setStringIgnoreCase(String stringIgnoreCase) {
		this.stringIgnoreCase = stringIgnoreCase;
	}

	public String getRegex() {
		return regex;
	}

	public void setRegex(String regex) {
		this.regex = regex;
	}

	public String getCss() {
		return css;
	}

	public void setCss(String jsoup) {
		css = jsoup;
	}

	public String getJson() {
		return json;
	}

	public void setJson(String jq) {
		json = jq;
	}

	public boolean alert(HttpResponseBody body) {

		if (string != null && !StringUtils.contains(body.toString(), string)) {
			return false;
		}

		if (stringIgnoreCase != null && !StringUtils.containsIgnoreCase(body.toString(), stringIgnoreCase)) {
			return false;
		}

		if (regex != null && !Pattern.compile(regex).matcher(body.toString()).find()) {
			return false;
		}

		if (css != null && Jsoup.parse(body.toString(), "http://example.com/").select(css).first() == null) {
			return false;
		}

		if (json != null && !JsonUtil.query(body, json).isPresent()) {
			return false;
		}

		return true;
	}

	public String evidence(HttpResponseBody body) {

		if (css != null) {
			Element elem = Jsoup.parse(body.toString(), "http://example.com/").select(css).first();
			if (elem != null) {
				return elem.outerHtml();
			}
		}

		if (json != null) {
			Optional<String> q = JsonUtil.query(body, json);
			if (q.isPresent()) {
				return q.get();
			}
		}

		if (regex != null) {
			Matcher m = Pattern.compile(regex).matcher(body.toString());
			if (m.find()) {
				return m.group();
			}
		}

		if (string != null && StringUtils.contains(body.toString(), string)) {
			return string;
		}

		if (stringIgnoreCase != null) {
			String str = body.toString();
			if (StringUtils.containsIgnoreCase(str, stringIgnoreCase)) {
				return StringUtils.substring(str, StringUtils.indexOfIgnoreCase(str, stringIgnoreCase),
						stringIgnoreCase.length());
			}
		}

		return StringUtils.EMPTY;
	}

}
