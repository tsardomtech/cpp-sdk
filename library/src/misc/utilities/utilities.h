#pragma once
#include <stdio.h>
#include <cstdint>
#include <optional>
#include <string_view>

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

#include "ntp_client/ntp_client.h"
#include "misc/structs.h"
#include "misc/errors.h"
#include "base64.h"

#include <cpr/cpr.h>
#include <nlohmann/json.h>
#include <cpr/HttpStatus.hpp>

#include <cryptopp/cryptlib.h>
#include <cryptopp/ecp.h>
#include <cryptopp/sha.h>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/asn.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/integer.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/secblock.h>
#include <cryptopp/pubkey.h>

namespace tsar::utilities {
	/// Opens a link in the users browser
	extern void open_link(const std::string& link);
	/// Verifies signature using ECDSA P256
	extern bool verify_signature(std::string& public_key, std::string& message, std::string& signature);
	/// Parses the data givin into a data_t structure
	extern data_t parse_data_json(nlohmann::json data_json);
	/// Returns the users hardware identification
	extern std::string get_hwid();
	/// Returns a string form of the enum
	extern std::string err_tostring(tsar_errors_t err_code);
}