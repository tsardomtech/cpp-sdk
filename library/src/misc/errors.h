#pragma once
#include <cstdint>

namespace tsar {
	enum tsar_status_t {
		/// Successful.
		success,

		/// Request to the TSAR server failed, server may be down.
		request_failed,
		/// The APP ID passed does not match to a TSAR APP.
		app_not_found,
		/// The HWID passed does not match to a user.
		user_not_found,
		/// TSAR server had an error and did not return an OK status.
		server_error,
		/// Failed to parse returned body into JSON.
		failed_to_parse_body,

		/// Failed to get the `data` field from the parsed JSON body.
		failed_to_get_data,
		/// Failed to get the `signature` field from the parsed JSON body.
		failed_to_get_signature,

		/// Failed to decode the `data` field from the parsed JSON body.
		failed_to_decode_data,
		/// Failed to decode the `signature` field from the parsed JSON body.
		failed_to_decode_signature,
		/// Failed to decode the client key from base64.
		failed_to_decode_pub_key,

		/// Failed to parse the `data` field into JSON.
		failed_to_parse_data,
		/// Failed to get the `timestamp` field.
		failed_to_get_timestamp,
		/// Failed to parse the `timestamp` field into u64.
		failed_to_parse_timestamp,

		/// Failed to build the verification key using der.
		failed_to_build_key,
		/// Failed to build signature using buffer.
		failed_to_build_signature,

		/// The response is old. Data may have been tampered with.
		old_response,
		/// Signature is not authentic. Data may have been tampered with.
		invalid_signature,

		/// Failed to open the user's default browser.
		failed_to_open_browser,
		/// User is not authorized to use the application.
		unauthorized,

		/// Failed to get the user's HWID.
		failed_to_get_hwid ,
	};
}