package org.zaproxy.zap.extension.aem.yaml;

public class ResponseYAML {

	private ResponseHeaderYAML header;

	private ResponseBodyYAML body;

	public ResponseHeaderYAML getHeader() {
		return this.header;
	}

	public void setHeader(ResponseHeaderYAML header) {
		this.header = header;
	}

	public ResponseBodyYAML getBody() {
		return this.body;
	}

	public void setBody(ResponseBodyYAML body) {
		this.body = body;
	}

}
