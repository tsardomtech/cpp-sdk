#include "client.h"
#include "misc/utilities/utilities.h"

namespace tsar {
	tsar_errors_t client::init(client_options_t options) {
		this->debug_print = options.debug_print;
		this->client_key = options.client_key;
		this->app_id = options.app_id;

		this->hwid = utilities::get_hwid();
		if (this->hwid.empty()) {
			this->dbgprint("Failed to get HWID\n");
			return failed_to_get_hwid;
		}

		tsar_errors_t auth_err = this->authenticate(
			this->app_id,
			this->hwid,
			this->client_key);

		if (auth_err != tsar_errors_t::success)
			return auth_err;

		return success;
	};

	tsar_errors_t client::authenticate(
		const std::string& app_id,
		const std::string& hwid,
		const std::string& client_key) {

		this->dbgprint("Authenticating...\n");

		tsar_errors_t validate_err = this->validate_user(
			app_id, hwid, client_key
		);

		switch (validate_err) {
			case success: {
				this->dbgprint("Authentication success.\n");

				if (subscription.user.username.has_value())
					this->dbgprint("Welcome, %s\n", subscription.user.username.value());

				return success;
			}
			case user_not_found: {
				this->dbgprint("Authentication failed: HWID not authorized. "
					"If a browser window did not open, please visit https://auth.tsar.cc/%s/%s to update your HWID.\n",
					app_id.c_str(), hwid.c_str());

				std::string url = std::format("https://auth.tsar.cc/{}/{}", app_id, hwid);
				utilities::open_link(url);

				return user_not_found;
			}
			default:
				break;
		}

		this->dbgprint("Authentication failed: %s. Please contact the software distributor for support.\n",
			utilities::err_tostring(validate_err).c_str());

		return validate_err;
	}

	tsar_errors_t client::validate_user(
		const std::string& app_id,
		const std::string& hwid,
		const std::string& client_key) {
		std::string pub_key = base64::from_base64(client_key);

		std::string url = std::format("https://tsar.cc/api/client/subscriptions/get?app={}&hwid={}", app_id, hwid);
		auto response = cpr::Get(cpr::Url(url));

		if (response.error) {
			this->dbgprint("%s\n", response.error.message.c_str());

			switch (response.status_code) {
				case HttpStatus::NotFound:
					return tsar_errors_t::app_not_found;
				case HttpStatus::Unauthorized:
					return tsar_errors_t::user_not_found;
				default:
					break;
			}

			if (response.error.code == cpr::ErrorCode::INTERNAL_ERROR) {
				return tsar_errors_t::server_error;
			}

			return tsar_errors_t::request_failed;
		}

		switch (response.status_code) {
			case HttpStatus::NotFound:
				return tsar_errors_t::app_not_found;
			case HttpStatus::Unauthorized:
				return tsar_errors_t::user_not_found;
			case HttpStatus::OK:
				break;
			default:
				return tsar_errors_t::server_error;
		}

		nlohmann::json data = nlohmann::json::parse(response.text, nullptr, false);
		if (data.is_discarded())
			return tsar_errors_t::failed_to_parse_body;

		if (!data["data"].is_string())
			return tsar_errors_t::failed_to_get_data;

		if (!data["signature"].is_string())
			return tsar_errors_t::failed_to_get_signature;

		std::string base64_data = data["data"].get<std::string>();
		std::optional<std::string> data_bytes_opt = base64::safe_from_base64(base64_data);

		if (!data_bytes_opt.has_value())
			return tsar_errors_t::failed_to_parse_data;

		std::string base64_signature = data["signature"].get<std::string>();
		std::string signature = base64::from_base64(base64_signature);

		std::string data_bytes = data_bytes_opt.value();
		nlohmann::json data_json = nlohmann::json::parse(data_bytes, nullptr, false);
		if (data_json.is_discarded())
			return tsar_errors_t::failed_to_parse_data;

		if (!data_json["hwid"].is_string())
			return tsar_errors_t::failed_to_get_signature;

		if (!data_json["timestamp"].is_number())
			return tsar_errors_t::failed_to_get_timestamp;

		data_t parsed_data = utilities::parse_data_json(data_json);

		if (hwid != parsed_data.hwid)
			return tsar_errors_t::old_response;

		/// NTP timestamp check
		int64_t timestamp = parsed_data.timestamp;
		int64_t ntp_timestamp = utilities::get_ntp_time();
		auto tt_system_time = std::chrono::system_clock::to_time_t(
			std::chrono::system_clock::now()
		);

		std::chrono::milliseconds duration;
		if (ntp_timestamp > tt_system_time)
			duration = std::chrono::milliseconds( (ntp_timestamp - tt_system_time) * 1000 );
		else
			duration = std::chrono::milliseconds( (tt_system_time - ntp_timestamp) * 1000 );

		if (duration.count() > 5000 || timestamp < (tt_system_time - 5))
			return tsar_errors_t::old_response;

		/// Signature check
		if (!utilities::verify_signature(pub_key, data_bytes, signature))
			return tsar_errors_t::invalid_signature;

		this->subscription = parsed_data.subscription;
		this->session = parsed_data.session;
		return tsar_errors_t::success;
	};

	std::string client::e2s(tsar_errors_t err) {
		return utilities::err_tostring(err);
	}
}
