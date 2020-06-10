/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.fuzz.payloads.processor;

import java.util.Collections;
import java.util.Map;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.ProcessingException;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;

/**
 * A {@code DefaultPayloadProcessor} that delegates the processing of the value
 * of a {@code
 * DefaultPayload} to a {@code DefaultPayloadProcessorScript}.
 *
 * @see DefaultPayload
 * @see DefaultPayloadProcessor
 * @see ScriptStringPayloadProcessor
 */
public class ScriptStringPayloadProcessorAdapter implements DefaultPayloadProcessor {

	private final ScriptWrapper scriptWrapper;
	private final Map<String, String> paramValues;
	private boolean initialised;
	private ScriptStringPayloadProcessor scriptProcessor;

	public ScriptStringPayloadProcessorAdapter(ScriptWrapper scriptWrapper) {
		validateScriptWrapper(scriptWrapper);
		this.scriptWrapper = scriptWrapper;
		paramValues = Collections.emptyMap();
	}

	private static void validateScriptWrapper(ScriptWrapper scriptWrapper) {
		if (scriptWrapper == null) {
			throw new IllegalArgumentException("Parameter scriptWrapper must not be null.");
		}
		if (!ScriptStringPayloadProcessor.TYPE_NAME.equals(scriptWrapper.getTypeName())) {
			throw new IllegalArgumentException("Parameter scriptWrapper must wrap a script of type \""
					+ ScriptStringPayloadProcessor.TYPE_NAME + "\".");
		}
	}

	public ScriptStringPayloadProcessorAdapter(ScriptWrapper scriptWrapper, Map<String, String> paramValues) {
		validateScriptWrapper(scriptWrapper);
		if (paramValues == null) {
			throw new IllegalArgumentException("Parameter paramValues must not be null.");
		}
		this.scriptWrapper = scriptWrapper;
		this.paramValues = paramValues;
	}

	@Override
	public DefaultPayload process(DefaultPayload payload) throws PayloadProcessingException {
		initialiseIfNotInitialised();

		try {
			String value = scriptProcessor.process(payload.getValue(), paramValues);
			if (value != null) {
				payload.setValue(value);
			}
		} catch (Exception e) {
			handleScriptException(e);
		}
		return payload;
	}

	private void initialiseIfNotInitialised() throws PayloadProcessingException {
		if (!initialised) {
			initialise();
			initialised = true;
		}

		if (scriptProcessor == null) {
			throw new PayloadProcessingException("Script '" + scriptWrapper.getName()
					+ "' does not implement the expected interface (ScriptStringPayloadProcessor).");
		}
	}

	private void initialise() throws PayloadProcessingException {
		ExtensionScript extensionScript = Control.getSingleton()
				.getExtensionLoader()
				.getExtension(ExtensionScript.class);
		if (extensionScript != null) {
			try {
				scriptProcessor = extensionScript.getInterface(scriptWrapper, ScriptStringPayloadProcessor.class);
				if (scriptProcessor != null) {
					validateRequiredParameters();
				} else {
					extensionScript.handleFailedScriptInterface(scriptWrapper,
							Constant.messages.getString(
									"fuzz.httpfuzzer.processor.scriptPayloadsProcessor.warnNoInterface.message",
									scriptWrapper.getName()));
				}
			} catch (Exception e) {
				handleScriptException(e);
			}
		}
	}

	private void validateRequiredParameters() throws ProcessingException {
		for (String requiredParamName : scriptProcessor.getRequiredParamsNames()) {
			String value = paramValues.get(requiredParamName);
			if (value == null || value.trim().isEmpty()) {
				throw new ProcessingException("Required parameter '" + requiredParamName + "' was not provided.");
			}
		}
	}

	private void handleScriptException(Exception cause) throws PayloadProcessingException {
		ExtensionScript extensionScript = Control.getSingleton()
				.getExtensionLoader()
				.getExtension(ExtensionScript.class);
		if (extensionScript != null) {
			extensionScript.setError(scriptWrapper, cause);
			extensionScript.setEnabled(scriptWrapper, false);
		}

		throw new PayloadProcessingException("Failed to process the payload:", cause);
	}

	@Override
	public PayloadProcessor<DefaultPayload> copy() {
		return new ScriptStringPayloadProcessorAdapter(scriptWrapper);
	}
}