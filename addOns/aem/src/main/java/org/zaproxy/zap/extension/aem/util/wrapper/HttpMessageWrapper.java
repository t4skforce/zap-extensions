package org.zaproxy.zap.extension.aem.util.wrapper;

import java.util.Arrays;
import java.util.Properties;

import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.network.HttpRequestBody;
import org.zaproxy.zap.network.HttpResponseBody;

public class HttpMessageWrapper extends HttpMessage {
	private static final Logger LOG = Logger.getLogger(HttpMessageWrapper.class);

	private Properties info = new Properties();

	public HttpMessageWrapper() {
		super();
	}

	public HttpMessageWrapper(HttpMessageWrapper message) {
		super(message);
		setInfo(message.getInfo());
	}

	public HttpMessageWrapper(HttpMessage message) {
		super(message);
	}

	public HttpMessageWrapper(HttpRequestHeader reqHeader, HttpRequestBody reqBody, HttpResponseHeader resHeader,
			HttpResponseBody resBody) {
		super(reqHeader, reqBody, resHeader, resBody);
	}

	public HttpMessageWrapper(HttpRequestHeader reqHeader, HttpRequestBody reqBody) {
		super(reqHeader, reqBody);
	}

	public HttpMessageWrapper(HttpRequestHeader reqHeader) {
		super(reqHeader);
	}

	public HttpMessageWrapper(String reqHeader, byte[] reqBody, String resHeader, byte[] resBody)
			throws HttpMalformedHeaderException {
		super(reqHeader, reqBody, resHeader, resBody);
	}

	public HttpMessageWrapper(URI uri) throws HttpMalformedHeaderException {
		super(uri);
	}

	public Properties getInfo() {
		return info;
	}

	public void setInfo(Properties info) {
		this.info = new Properties(info);
	}

	@Override
	public HttpMessageWrapper cloneAll() {
		HttpMessageWrapper newMsg = cloneRequest();
		copyResponseInto(newMsg);
		return newMsg;
	}

	@Override
	public HttpMessageWrapper cloneRequest() {
		HttpMessageWrapper newMsg = new HttpMessageWrapper();
		copyRequestInto(newMsg);
		newMsg.setInfo(getInfo());
		return newMsg;
	}

	private void copyResponseInto(HttpMessage newMsg) {
		if (!getResponseHeader().isEmpty()) {
			try {
				newMsg.getResponseHeader().setMessage(getResponseHeader().toString());
			} catch (HttpMalformedHeaderException e) {
			}
			newMsg.setResponseBody(getResponseBody().getBytes());
		}
	}

	private void copyRequestInto(HttpMessageWrapper newMsg) {
		if (!getRequestHeader().isEmpty()) {
			try {
				newMsg.getRequestHeader().setMessage(getRequestHeader().toString());
			} catch (HttpMalformedHeaderException e) {
				LOG.error(e.getMessage(), e);
			}
			newMsg.setRequestBody(getRequestBody().getBytes());
		}
	}

	@Override
	public int hashCode() {
		return StringUtils.join(Arrays.asList(getRequestHeader().toString(), getRequestBody().toString(),
				getResponseHeader().toString(), getResponseBody().toString()), "\r\n").hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		HttpMessageWrapper other = (HttpMessageWrapper) obj;
		if (!getRequestHeader().toString().equals(other.getRequestHeader().toString())) {
			return false;
		}
		if (!getRequestBody().toString().equals(other.getRequestBody().toString())) {
			return false;
		}
		if (!getResponseHeader().toString().equals(getResponseHeader().toString())) {
			return false;
		}
		if (!getResponseBody().toString().equals(getRequestBody().toString())) {
			return false;
		}
		return true;
	}

}
