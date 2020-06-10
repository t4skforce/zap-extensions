 /**
  * Processes the payload.
  * 
  * Called for each payload that needs to be processed.
  * 
  * @param {string} payload - The payload before being injected into the message.
  * @param params - parameters given
  * @return {string}
  */
String process(String payload, Map<String,String> params) {
	String format = params.get("format")
	if(payload.isDouble()) {
		return String.format(format, payload.toDouble())
	} else if(payload.isFloat()) {
		return String.format(format, payload.toFloat()())
	} else if(payload.isInteger()) {
		return String.format(format, payload.toInteger())
	} else if(payload.isLong()) {
		return String.format(format, payload.toLong())
	}
	return payload
}

/**
 * This function is called during the script loading to obtain a list of the names of the required configuration parameters,
 * that will be shown in the Add Message Processor Dialog for configuration. They can be used
 * to input dynamic data into the script, from the user interface
*/
String[] getRequiredParamsNames() {
	return ["format"]
}
