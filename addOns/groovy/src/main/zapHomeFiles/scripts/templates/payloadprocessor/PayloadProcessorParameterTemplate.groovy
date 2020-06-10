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
   return String.format("%s-%s", payload, params.get("exampleParam1"))
}

/**
 * This function is called during the script loading to obtain a list of the names of the required configuration parameters,
 * that will be shown in the Add Message Processor Dialog for configuration. They can be used
 * to input dynamic data into the script, from the user interface
*/
String[] getRequiredParamsNames(){
	return ["exampleParam1", "exampleParam2"];
}

/**
 * This function is called during the script loading to obtain a list of the names of the optional configuration parameters,
 * that will be shown in the Add Message Processor Dialog for configuration. They can be used
 * to input dynamic data into the script, from the user interface
*/
String[] getOptionalParamsNames(){
	return ["exampleParam3"];
}