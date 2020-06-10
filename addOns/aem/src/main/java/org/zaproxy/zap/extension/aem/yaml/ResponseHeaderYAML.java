package org.zaproxy.zap.extension.aem.yaml;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpResponseHeader;

public class ResponseHeaderYAML {

	private Integer status = 200;

	private Boolean html;

	private Boolean text;

	private Boolean image;

	private Boolean empty;

	private Boolean json;

	private Boolean xml;

	private Boolean javascript;

	private String regex;

	public Integer getStatus() {
		return status;
	}

	public void setStatus(Integer status) {
		this.status = status;
	}

	public Boolean getHtml() {
		return html;
	}

	public void setHtml(Boolean html) {
		this.html = html;
	}

	public Boolean getText() {
		return text;
	}

	public void setText(Boolean text) {
		this.text = text;
	}

	public Boolean getImage() {
		return image;
	}

	public void setImage(Boolean image) {
		this.image = image;
	}

	public Boolean getEmpty() {
		return empty;
	}

	public void setEmpty(Boolean empty) {
		this.empty = empty;
	}

	public Boolean getJson() {
		return json;
	}

	public void setJson(Boolean json) {
		this.json = json;
	}

	public String getRegex() {
		return regex;
	}

	public void setRegex(String regex) {
		this.regex = regex;
	}

	public Boolean getXml() {
		return xml;
	}

	public void setXml(Boolean xml) {
		this.xml = xml;
	}

	public Boolean getJavascript() {
		return javascript;
	}

	public void setJavascript(Boolean javascript) {
		this.javascript = javascript;
	}

	public boolean alert(HttpResponseHeader header) {
		if (status != null && header.getStatusCode() != status) {
			return false;
		}
		if (html != null && header.isHtml() != html.booleanValue()) {
			return false;
		}
		if (text != null && header.isText() != text.booleanValue()) {
			return false;
		}
		if (image != null && header.isImage() != image.booleanValue()) {
			return false;
		}
		if (empty != null && header.isEmpty() != empty.booleanValue()) {
			return false;
		}
		if (xml != null && header.isXml() != xml.booleanValue()) {
			return false;
		}
		if (json != null && header.isJson() != json.booleanValue()) {
			return false;
		}
		if (javascript != null && header.isJavaScript() != javascript.booleanValue()) {
			return false;
		}
		if (getRegex() != null && !Pattern.compile(regex).matcher(header.toString()).find()) {
			return false;
		}
		return true;
	}

	public String evidence(HttpResponseHeader header) {
		String retVal = null;
		if (status != null && header.getStatusCode() != status) {
			retVal = header.toString().split("\n")[0];
		}

		if (html != null && header.isHtml() == html.booleanValue()) {
			retVal = header.getHeader(HttpHeader.CONTENT_TYPE);
		}

		if (text != null && header.isText() == text.booleanValue()) {
			retVal = header.getHeader(HttpHeader.CONTENT_TYPE);
		}

		if (image != null && header.isImage() == image.booleanValue()) {
			retVal = header.getHeader(HttpHeader.CONTENT_TYPE);
		}

		if (empty != null && header.isEmpty() == empty.booleanValue()) {
			retVal = "";
		}

		if (xml != null && header.isXml() == xml.booleanValue()) {
			return header.getHeader(HttpHeader.CONTENT_TYPE);
		}

		if (json != null && header.isJson() == json.booleanValue()) {
			retVal = header.getHeader(HttpHeader.CONTENT_TYPE);
		}

		if (javascript != null && header.isJavaScript() == javascript.booleanValue()) {
			retVal = header.getHeader(HttpHeader.CONTENT_TYPE);
		}

		if (getRegex() != null) {
			Matcher m = Pattern.compile(regex).matcher(header.toString());
			if (m.find()) {
				retVal = m.group();
			}
		}

		return retVal;
	}

}
