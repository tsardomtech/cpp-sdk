#include "utilities.h"

namespace tsar {
    void utilities::open_link(const std::string& link) {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        system(("start " + link).c_str());
#elif defined(__linux__) || defined(__unix__)
        system(("xdg-open " + link).c_str());
#elif defined(__APPLE__) && defined(__MACH__)
        system(("open " + link).c_str());
#endif
    };

    bool utilities::verify_signature(std::string& public_key, std::string& message, std::string& signature) {
        CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier verifier;
        CryptoPP::StringSource pub_key_source(public_key, true);
        verifier.AccessKey().Load(pub_key_source);

        CryptoPP::byte* message_array = reinterpret_cast<CryptoPP::byte*>(message.data());
        CryptoPP::byte* signature_array = reinterpret_cast<CryptoPP::byte*>(signature.data());

        return verifier.VerifyMessage(message_array, message.size(), signature_array, signature.size());
    }

    data_t utilities::parse_data_json(nlohmann::json data_json) {
        data_t data = {};
        {
            data.hwid = data_json["hwid"].get<std::string>();
            data.session = data_json["session"].get<std::string>();
            data.timestamp = data_json["timestamp"].get<int64_t>();
        }

        nlohmann::json subscription_json = data_json["subscription"];
        subscription_t subscription = {};
        {
            subscription.id = subscription_json["id"].get<std::string>();
            subscription.expires = (subscription_json["expires"].is_null() ? std::nullopt
                : std::make_optional<int64_t>(subscription_json["expires"].get<int64_t>()));
        }

        nlohmann::json user_json = subscription_json["user"];
        user_t user = {};
        {
            user.id = user_json["id"].get<std::string>();

            user.username = (user_json["username"].is_null() ? std::nullopt
                : std::make_optional<std::string>(user_json["username"].get<std::string>()));

            user.avatar = (user_json["avatar"].is_null() ? std::nullopt
                : std::make_optional<std::string>(user_json["avatar"].get<std::string>()));
        }

        subscription.user = user;
        data.subscription = subscription;

        return data;
    };

	std::string utilities::get_hwid() {
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
        HKEY hKey;
        DWORD bufLen = 1024;
        char szBuffer[1024];
        DWORD dwDataType;

        std::string subKey = "SOFTWARE\\Microsoft\\Cryptography";
        std::string valueName = "MachineGuid";

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueEx(hKey, valueName.c_str(), 0, &dwDataType, (LPBYTE)szBuffer, &bufLen) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return std::string(szBuffer);
            }
            RegCloseKey(hKey);
        }

#elif defined(__linux__) || defined(__unix__)
        std::vector<std::string> paths = { "/var/lib/dbus/machine-id", "/etc/machine-id" };
        for (std::string& path : paths) {
            FILE* fptr;

            // Open a file in read mode
            fptr = fopen(path.c_str(), "r");
            if (fptr) {
                char mySID[100];

                fgets(mySID, 100, fptr);
                std::string SIDString = std::string(mySID);
                SIDString.erase(remove_if(SIDString.begin(), SIDString.end(), isspace), SIDString.end());
                fclose(fptr);
                return SIDString;
            }

            fclose(fptr);
        }

        std::cout << "cannot find SID for your Linux system\n";
#elif defined(__APPLE__) && defined(__MACH__)
        std::array<char, 128> buffer;
        std::string result;
        std::shared_ptr<FILE> pipe(popen("ioreg -rd1 -c IOExpertPlatformDevice", "r"), pclose);
        if (!pipe)
            throw std::runtime_error("popen() failed!");

        while (!feof(pipe.get())) {
            if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
                result += buffer.data();
        }

        return result;
#endif
        return "";
	};

    std::string utilities::err_tostring(tsar_status_t err_code) {
        switch (err_code) {
            case success:
                return "Success";
            case request_failed:
                return "Request failed";
            case app_not_found:
                return "App not found";
            case user_not_found:
                return "User not found";
            case server_error:
                return "Server error";
            case failed_to_parse_body:
                return "Failed to parse body";
            case failed_to_get_data:
                return "Failed to get data";
            case failed_to_get_signature:
                return "Failed to get signature";
            case failed_to_decode_data:
                return "Failed to decode data";
            case failed_to_decode_signature:
                return "Failed to decode signature";
            case failed_to_decode_pub_key:
                return "Failed to decode public key";
            case failed_to_parse_data:
                return "Failed to parse data";
            case failed_to_get_timestamp:
                return "Failed to get timestamp";
            case failed_to_parse_timestamp:
                return "Failed to parse timestamp";
            case failed_to_build_key:
                return "Failed to build key";
            case failed_to_build_signature:
                return "Failed to build signature";
            case old_response:
                return "Old response";
            case invalid_signature:
                return "Invalid Signature";
            case failed_to_open_browser:
                return "Failed to open browser";
            case failed_to_get_hwid:
                return "Failed to get hwid";
            case unauthorized:
            default:
                break;
        }

        return "Unauthorized";
    };
}