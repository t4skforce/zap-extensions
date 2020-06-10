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
package org.zaproxy.zap.extension.fuzz.payloads.ui.processors;

import java.awt.event.ItemEvent;
import java.util.List;
import java.util.Map;

import javax.swing.GroupLayout;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.zap.extension.fuzz.ScriptUIEntry;
import org.zaproxy.zap.extension.fuzz.httpfuzzer.processors.HttpFuzzerProcessorScript;
import org.zaproxy.zap.extension.fuzz.payloads.DefaultPayload;
import org.zaproxy.zap.extension.fuzz.payloads.processor.ScriptStringPayloadProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.processor.ScriptStringPayloadProcessorAdapter;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.ScriptStringPayloadProcessorAdapterUIHandler.ScriptStringPayloadProcessorAdapterUI;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptWrapper;
import org.zaproxy.zap.utils.SortedComboBoxModel;
import org.zaproxy.zap.view.DynamicFieldsPanel;

public class ScriptStringPayloadProcessorAdapterUIHandler implements
		PayloadProcessorUIHandler<DefaultPayload, ScriptStringPayloadProcessorAdapter, ScriptStringPayloadProcessorAdapterUI> {

	private static final Logger LOG = Logger.getLogger(ScriptStringPayloadProcessorAdapterUIHandler.class);

	private static final String PROCESSOR_NAME = Constant.messages.getString("fuzz.payload.processor.script.name");

	private final ExtensionScript extensionScript;

	public ScriptStringPayloadProcessorAdapterUIHandler(ExtensionScript extensionScript) {
		this.extensionScript = extensionScript;
	}

	@Override
	public String getName() {
		return PROCESSOR_NAME;
	}

	@Override
	public Class<ScriptStringPayloadProcessorAdapterUI> getPayloadProcessorUIClass() {
		return ScriptStringPayloadProcessorAdapterUI.class;
	}

	@Override
	public Class<ScriptStringPayloadProcessorAdapterUIPanel> getPayloadProcessorUIPanelClass() {
		return ScriptStringPayloadProcessorAdapterUIPanel.class;
	}

	@Override
	public ScriptStringPayloadProcessorAdapterUIPanel createPanel() {
		return new ScriptStringPayloadProcessorAdapterUIPanel(
				extensionScript.getScripts(ScriptStringPayloadProcessor.TYPE_NAME));
	}

	public static class ScriptStringPayloadProcessorAdapterUI
			implements PayloadProcessorUI<DefaultPayload, ScriptStringPayloadProcessorAdapter> {

		private final ScriptWrapper scriptWrapper;
		private final Map<String, String> paramsValues;

		public ScriptStringPayloadProcessorAdapterUI(ScriptWrapper scriptWrapper, Map<String, String> paramsValues) {
			this.scriptWrapper = scriptWrapper;
			this.paramsValues = paramsValues;
		}

		public ScriptWrapper getScriptWrapper() {
			return scriptWrapper;
		}

		public Map<String, String> getParamsValues() {
			return paramsValues;
		}

		@Override
		public Class<ScriptStringPayloadProcessorAdapter> getPayloadProcessorClass() {
			return ScriptStringPayloadProcessorAdapter.class;
		}

		@Override
		public String getName() {
			return PROCESSOR_NAME;
		}

		@Override
		public boolean isMutable() {
			return true;
		}

		@Override
		public String getDescription() {
			return scriptWrapper.getName();
		}

		@Override
		public ScriptStringPayloadProcessorAdapter getPayloadProcessor() {
			return new ScriptStringPayloadProcessorAdapter(scriptWrapper, paramsValues);
		}

		@Override
		public ScriptStringPayloadProcessorAdapterUI copy() {
			return this;
		}
	}

	public static class ScriptStringPayloadProcessorAdapterUIPanel extends
			AbstractProcessorUIPanel<DefaultPayload, ScriptStringPayloadProcessorAdapter, ScriptStringPayloadProcessorAdapterUI> {

		private static final String SCRIPT_FIELD_LABEL = Constant.messages
				.getString("fuzz.payload.processor.script.script.label");

		private final JPanel fieldsPanel;
		private final JComboBox<ScriptUIEntry> scriptComboBox;
		private DynamicFieldsPanel scriptParametersPanel;

		public ScriptStringPayloadProcessorAdapterUIPanel(List<ScriptWrapper> scriptWrappers) {
			scriptComboBox = new JComboBox<>(new SortedComboBoxModel<ScriptUIEntry>());
			addScriptsToScriptComboBox(scriptWrappers);
			scriptComboBox.addItemListener(e -> {
				if (e.getStateChange() == ItemEvent.SELECTED) {
					updateScriptParametersPanel((ScriptStringPayloadProcessorScriptUIEntry) e.getItem());
				}
			});
			scriptParametersPanel = new DynamicFieldsPanel(HttpFuzzerProcessorScript.EMPTY_PARAMS);
			fieldsPanel = new JPanel();
			setupFieldsPanel();
		}

		private void addScriptsToScriptComboBox(List<ScriptWrapper> scriptWrappers) {
			for (ScriptWrapper scriptWrapper : scriptWrappers) {
				if (scriptWrapper.isEnabled()) {
					scriptComboBox.addItem(new ScriptStringPayloadProcessorScriptUIEntry(scriptWrapper));
				}
			}
			scriptComboBox.setSelectedIndex(-1);
		}

		private void setupFieldsPanel() {
			GroupLayout layout = new GroupLayout(fieldsPanel);
			fieldsPanel.setLayout(layout);
			layout.setAutoCreateGaps(true);

			JLabel scriptLabel = new JLabel(SCRIPT_FIELD_LABEL);
			scriptLabel.setLabelFor(scriptComboBox);

			JScrollPane parametersScrollPane = new JScrollPane(scriptParametersPanel);

			layout.setHorizontalGroup(layout.createParallelGroup()
					.addGroup(layout.createSequentialGroup().addComponent(scriptLabel).addComponent(scriptComboBox))
					.addComponent(parametersScrollPane));

			layout.setVerticalGroup(layout.createSequentialGroup()
					.addGroup(layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
							.addComponent(scriptLabel)
							.addComponent(scriptComboBox))
					.addComponent(parametersScrollPane));
		}

		private void updateScriptParametersPanel(ScriptStringPayloadProcessorScriptUIEntry scriptUIEntry) {
			String[] requiredParameters = HttpFuzzerProcessorScript.EMPTY_PARAMS;
			String[] optionalParameters = HttpFuzzerProcessorScript.EMPTY_PARAMS;

			if (scriptUIEntry != null) {
				try {
					if (!scriptUIEntry.isDataLoaded()) {
						ScriptStringPayloadProcessor script = initialiseImpl(scriptUIEntry.getScriptWrapper());
						scriptUIEntry.setParameters(script.getRequiredParamsNames(), script.getOptionalParamsNames());
					}
					requiredParameters = scriptUIEntry.getRequiredParameters();
					optionalParameters = scriptUIEntry.getOptionalParameters();
				} catch (Exception ex) {
					LOG.error(ex.getMessage(), ex);
					scriptComboBox.setSelectedIndex(-1);
					scriptComboBox.removeItem(scriptUIEntry);
					showValidationMessageDialog(
							Constant.messages.getString("fuzz.payload.processor.script.warnNoInterface.message"),
							Constant.messages.getString("fuzz.payload.processor.script.warnNoInterface.title"));
				}
			}

			scriptParametersPanel.setFields(requiredParameters, optionalParameters);

			fieldsPanel.revalidate();
			fieldsPanel.repaint();
		}

		@Override
		public JPanel getComponent() {
			return fieldsPanel;
		}

		@Override
		public void setPayloadProcessorUI(ScriptStringPayloadProcessorAdapterUI payloadProcessorUI) {
			scriptComboBox.setSelectedItem(new ScriptUIEntry(payloadProcessorUI.getScriptWrapper()));
			scriptParametersPanel.bindFieldValues(payloadProcessorUI.paramsValues);
		}

		@Override
		public ScriptStringPayloadProcessorAdapterUI getPayloadProcessorUI() {
			ScriptStringPayloadProcessorScriptUIEntry entry = (ScriptStringPayloadProcessorScriptUIEntry) scriptComboBox
					.getSelectedItem();
			return new ScriptStringPayloadProcessorAdapterUI(entry.getScriptWrapper(),
					scriptParametersPanel.getFieldValues());
		}

		@Override
		public ScriptStringPayloadProcessorAdapter getPayloadProcessor() {
			if (!validate()) {
				return null;
			}
			ScriptStringPayloadProcessorScriptUIEntry entry = (ScriptStringPayloadProcessorScriptUIEntry) scriptComboBox
					.getSelectedItem();
			return new ScriptStringPayloadProcessorAdapter(entry.getScriptWrapper(),
					scriptParametersPanel.getFieldValues());
		}

		@Override
		public void clear() {
			scriptComboBox.setSelectedIndex(-1);
			scriptParametersPanel.clearFields();
		}

		@Override
		public boolean validate() {
			if (scriptComboBox.getSelectedIndex() == -1) {
				showValidationMessageDialog(
						Constant.messages
								.getString("fuzz.httpfuzzer.processor.scriptProcessor.panel.warnNoScript.message"),
						Constant.messages
								.getString("fuzz.httpfuzzer.processor.scriptProcessor.panel.warnNoScript.title"));
				return false;
			}

			try {
				scriptParametersPanel.validateFields();
			} catch (IllegalStateException ex) {
				showValidationMessageDialog(ex.getMessage(),
						Constant.messages.getString("fuzz.payload.processor.script.panel.warn.title"));
				return false;
			}
			return true;
		}

		private void showValidationMessageDialog(Object message, String title) {
			JOptionPane.showMessageDialog(null, message, title, JOptionPane.INFORMATION_MESSAGE);
			scriptComboBox.requestFocusInWindow();
		}

		private static class ScriptStringPayloadProcessorScriptUIEntry extends ScriptUIEntry {

			private String[] requiredParameters;
			private String[] optionalParameters;
			private boolean dataLoaded;

			public ScriptStringPayloadProcessorScriptUIEntry(ScriptWrapper scriptWrapper) {
				super(scriptWrapper);
			}

			public boolean isDataLoaded() {
				return dataLoaded;
			}

			public void setParameters(String[] requiredParameters, String[] optionalParameters) {
				this.requiredParameters = requiredParameters;
				this.optionalParameters = optionalParameters;
				dataLoaded = true;
			}

			public String[] getRequiredParameters() {
				return requiredParameters;
			}

			public String[] getOptionalParameters() {
				return optionalParameters;
			}
		}
	}

	private static ScriptStringPayloadProcessor initialiseImpl(ScriptWrapper scriptWrapper) throws Exception {
		ExtensionScript extensionScript = Control.getSingleton()
				.getExtensionLoader()
				.getExtension(ExtensionScript.class);
		if (extensionScript != null) {
			return extensionScript.getInterface(scriptWrapper, ScriptStringPayloadProcessor.class);
		}
		return null;
	}
}