#ifndef TSAR_HPP
#define TSAR_HPP

#include <string>
#include <sstream>
#include <curl/curl.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "../nlohmann/json.hpp"
#include <iostream>
#include <unordered_map>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

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
/// ---!!! UTILS !!!---

const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::string &input)
{
    std::string encoded;
    int i = 0, j = 0;
    unsigned char char_array_3[3], char_array_4[4];

    for (const char &ch : input)
    {
        char_array_3[i++] = ch;
        if (i == 3)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                encoded += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; j < i + 1; j++)
            encoded += base64_chars[char_array_4[j]];

        while (i++ < 3)
            encoded += '=';
    }

    return encoded;
}

std::string base64_decode(const std::string &input)
{
    std::string decoded;
    int i = 0, j = 0;
    unsigned char char_array_4[4], char_array_3[3];

    for (const char &ch : input)
    {
        if (ch == '=')
            break;
        char_array_4[i++] = ch;
        if (i == 4)
        {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; i < 3; i++)
                decoded += char_array_3[i];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

        for (j = 0; j < i - 1; j++)
            decoded += char_array_3[j];
    }

    return decoded;
}

/// @brief Get the hardware ID of the system
/// @return std::string
std::string get_hwid()
{
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    HKEY hKey;
    DWORD bufLen = 1024;
    char szBuffer[1024];
    DWORD dwDataType;

    std::string subKey = "SOFTWARE\\Microsoft\\Cryptography";
    std::string valueName = "MachineGuid";

    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS)
    {
        if (RegQueryValueEx(hKey, valueName.c_str(), 0, &dwDataType, (LPBYTE)szBuffer, &bufLen) == ERROR_SUCCESS)
        {
            RegCloseKey(hKey);
            return std::string(szBuffer);
        }
        RegCloseKey(hKey);
    }

#elif defined(__linux__) || defined(__unix__)
    std::vector<std::string> paths = {"/var/lib/dbus/machine-id", "/etc/machine-id"};
    for (std::string &path : paths)
    {
        FILE *fptr;

        // Open a file in read mode
        fptr = fopen(path.c_str(), "r");
        if (fptr)
        {
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

    while (!feof(pipe.get()))
    {
        if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
            result += buffer.data();
    }

    return result;
#endif
    return "";
}

/// @brief Verify the signature of the data
/// @param pub_key Public key
/// @param data Data to verify
/// @param signature Signature to verify
/// @return bool - True if the signature is valid, false otherwise
bool verify_signature(EVP_PKEY *pub_key, const std::string &data, const std::string &signature)
{
    EVP_MD_CTX *mdctx = NULL;
    int res = 0;

    if (!(mdctx = EVP_MD_CTX_create()))
    {
        return false;
    }

    if (1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pub_key))
    {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    if (1 != EVP_DigestVerifyUpdate(mdctx, data.c_str(), data.size()))
    {
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    res = EVP_DigestVerifyFinal(mdctx, (unsigned char *)signature.c_str(), signature.size());

    EVP_MD_CTX_free(mdctx);

    return res == 1;
}

/// @brief Get the NTP time difference
/// @return int - NTP time difference in seconds
int get_ntp_diff()
{
    char *hostname = (char *)"200.20.186.76";
    int portno = 123;
    int maxlen = 1024;
    int i;
    unsigned char msg[48] = {010, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned long buf[maxlen];

    struct protoent *proto;
    struct sockaddr_in server_addr;
    int s;
    long tmit;

    proto = getprotobyname("udp");
    s = socket(PF_INET, SOCK_DGRAM, proto->p_proto);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(hostname);
    server_addr.sin_port = htons(portno);

    i = sendto(s, msg, sizeof(msg), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));

    struct sockaddr saddr;
    socklen_t saddr_l = sizeof(saddr);
    i = recvfrom(s, buf, 48, 0, &saddr, &saddr_l);

    tmit = ntohl((time_t)buf[4]);
    tmit -= 2208988800U;

    i = time(0);
    time_t diff = i - tmit;

    return abs(diff);
}

/// @brief Convert data bytes to string
/// @param data_bytes Data bytes
/// @return std::string
std::string data_bytes_to_string(const std::string &data_bytes)
{
    return std::string(data_bytes.begin(), data_bytes.end());
}

/// @brief Open a URL in the default browser
/// @param url URL to open
void open_url(const std::string &url)
{
#if defined(_WIN32) || defined(_WIN64) || defined(__CYGWIN__)
    system(("start " + url).c_str());

#elif defined(__linux__) || defined(__unix__)
    system(("xdg-open " + url).c_str());

#elif defined(__APPLE__) && defined(__MACH__)
    system(("open " + url).c_str());

#endif
}

/// @brief Perform a `GET` request
/// @param url URL to get
/// @param response Response
/// @param write_callback Callback function
/// @param response_code Response code
/// @return int - 1 if the request was successful, 0 otherwise
int get_request(const std::string &url, std::string &response, size_t write_callback(void *cnts, size_t size, size_t nmemb, void *userp), int &response_code)
{
    CURL *curl = curl_easy_init();

    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        curl_easy_cleanup(curl);

        return 1;
    }

    return 0;
}

/// @brief Validate the result
/// @param response Response
/// @param signature Signature
/// @param pub_key Public key
/// @return int - 1 if the result is valid, 0 otherwise
int validate_result(const std::string &response, const std::string &signature, EVP_PKEY *pub_key)
{
    std::string decoded_data = base64_decode(response);
    std::string decoded_signature = base64_decode(signature);

    std::string json_string = data_bytes_to_string(decoded_data);

    bool result = verify_signature(pub_key, json_string, decoded_signature);

    if (result == true)
    {
        return 1;
    }

    return 0;
}

/// ---!!! STRUCTS !!!---

/// User object
typedef struct User
{
    std::string id;
    std::string username;
    std::string avatar;
} User;

/// Subscription object
typedef struct Subscription
{
    std::string id;
    long long expires;
    User user;
} Subscription;

/// Data returned by the server when fetching a subscription.
typedef struct Data
{
    Subscription subscription;
    long long timestamp;
    std::string hwid;
    std::string session;
} Data;

Data string_to_data(const std::string &json_string)
{
    nlohmann::json json = nlohmann::json::parse(json_string);

    Data data;

    data.subscription.id = json["subscription"]["id"];
    if (json["subscription"]["expires"].is_number())
    {
        data.subscription.expires = json["subscription"]["expires"];
    }

    data.subscription.user.id = json["subscription"]["user"]["id"];
    if (json["subscription"]["user"]["username"].is_string())
    {
        data.subscription.user.username = json["subscription"]["user"]["username"];
    }
    if (json["subscription"]["user"]["avatar"].is_string())
    {
        data.subscription.user.avatar = json["subscription"]["user"]["avatar"];
    }

    data.timestamp = json["timestamp"];
    data.hwid = json["hwid"];
    data.session = json["session"];

    return data;
}

/// ---!!! CLIENT !!!---

/// The TSAR Client struct. Used to interact with the API after it's initialized.
class Client
{
public:
    /// The ID of your TSAR app. Should be in UUID format: 00000000-0000-0000-0000-000000000000
    std::string app_id;
    /// The public decryption key for your TSAR app. Should be in base64 format.
    std::string client_key;
    /// The HWID of the authenticated user.
    std::string hwid;
    /// Client session is used to query the client API as a user.
    std::string session;
    /// The subscription object of the user that authenticated.
    Subscription subscription;

    /// @brief Construct a new Client object
    /// @param app_id App id
    /// @param client_key Client key
    Client(std::string &app_id, std::string &client_key) : app_id(app_id), client_key(client_key)
    {
        this->hwid = get_hwid();

        if (this->hwid.empty())
        {
            std::cout << "Failed to get HWID\n";
            exit(1);
        }

        Data data = this->validate_user();

        this->subscription = data.subscription;
        this->session = data.session;
    }

    /// @brief Validate the user
    /// @return Data - Data object containing the subscription and other information
    Data validate_user()
    {
        std::string pub_key_bytes = base64_decode(client_key);

        EVP_PKEY *pub_key = EVP_PKEY_new();

        std::stringstream ss;
        ss << "https://tsar.cc/api/client/subscriptions/get?app=" << this->app_id
           << "&hwid=" << this->hwid;
        std::string url = ss.str();

        // std::cout << "URL: " << url << "\n";

        std::string response;
        int response_code;

        if (get_request(url, response, write_callback, response_code) == 1)
        {
            if (response_code == 401)
            {
                std::cout << "Subscription not found. Please re-run this command once you authenticate.\n";
                std::string url = "https://tsar.cc/auth/" + this->app_id + "/" + hwid;

                open_url(url);

                exit(1);
            }

            nlohmann::json data = nlohmann::json::parse(response);

            std::string signature = data["signature"];
            std::string data_bytes = data["data"];

            std::string decoded_data = base64_decode(data_bytes);
            std::string decoded_signature = base64_decode(signature);

            std::string json_string = data_bytes_to_string(decoded_data);

            if (validate_result(json_string, decoded_signature, pub_key) != 0)
            {
                std::cout << "Failed to validate result\n";
                return Data();
            }

            Data dataobj = string_to_data(json_string);

            long long timestamp = dataobj.timestamp;
            long long current_time = time(0);

            if (timestamp < current_time || get_ntp_diff() > 1)
            {
                std::cout << "Old request\n";
                return Data();
            }
        }
        else
        {
            std::cout << "Failed to get request\n";
            return Data();
        }
    }

private:
    static size_t write_callback(void *cnts, size_t size, size_t nmemb, void *userp)
    {
        ((std::string *)userp)->append((char *)cnts, size * nmemb);
        return size * nmemb;
    }
};

#endif
