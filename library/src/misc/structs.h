#pragma once
#include <cstdint>
#include <optional>
#include <string>

namespace tsar {
	typedef struct client_options_t {
		std::string app_id;
		std::string client_key;
		bool debug_print;

		client_options_t(std::string app_id, std::string client_key, bool debug_print = false)
			: app_id(app_id), client_key(client_key), debug_print(debug_print) {};
	} client_options_t;

	typedef struct user_t {
		std::string id;
		std::optional<std::string> username;
		std::optional<std::string> avatar;
	}user_t;

	typedef struct subscription_t {
		std::string id;
		std::optional<int64_t> expires;
		user_t user;
	} subscription_t;

	typedef struct data_t {
		subscription_t subscription;
		uint64_t timestamp;
		std::string hwid;
		std::string session;
	} data_t;
}