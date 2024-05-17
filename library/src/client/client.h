#pragma once

#ifndef TSARCLIENT_H
#define TSARCLIENT_H

#include <stdio.h>
#include <cstdint>
#include <optional>

#include "misc/structs.h"
#include "misc/errors.h"

#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
#include <windows.h>

#elif defined(__linux__) || defined(__unix__)
#include <fstream>

#elif defined(__APPLE__) && defined(__MACH__)
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <array>
#endif


namespace tsar {
	class client {
	public:
		/// The ID of your TSAR app. Should be in UUID format: 00000000-0000-0000-0000-000000000000
		std::string app_id;
		/// The public decryption key for your TSAR app. Should be in base64 format.
		std::string client_key;
		/// Client session is used to query the client API as a user.
		std::string session;
		/// The HWID of the authenticated user.
		std::string hwid;
		/// The subscription object of the user that authenticated.
		subscription_t subscription;
		/// Whether TSAR should print debug statements regarding auth.
		bool debug_print;
	public:
		client() {};

		/// Initializes a new TSAR client using `app_id` and `client_key` variables.
		tsar_status_t init(client_options_t options);

		/// Starts an authentication flow which attempts to authenticate the user.
		/// If the user's HWID is not already authorized, the function opens the user's default browser to authenticate them.
		tsar_status_t authenticate(
			const std::string& app_id,
			const std::string& hwid,
			const std::string& client_key);

		/// Check if a HWID is authorized to use the application. Takes custom parameters.
		tsar_status_t validate_user(
			const std::string& app_id,
			const std::string& hwid,
			const std::string& client_key);

		std::string e2s(tsar_status_t err);
	private:
		void dbgprint(const char* format, ...) {
			if (!debug_print)
				return;

			va_list arg_list;

			printf("[TSAR]: ");
			va_start(arg_list, format);
			vprintf(format, arg_list);
			va_end(arg_list);
		}
	};
}
#endif
