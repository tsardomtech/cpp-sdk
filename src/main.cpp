#include "../include/tsar/client.hpp"
#include <iostream>

int main()
{
    std::string appId = "9654e365-003c-4044-9620-548d0692410b";
    std::string publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExqFKMC375sH2Y6wJ93buRNTk/T4pUXxBb3q4g6azD3PpeUmrnVZVN336CoLDtokhrsJ1SxPj6fGzE3YGkvHQ0Q==";

    Client client(appId, publicKey);

    std::cout << get_ntp_diff() << '\n';
    std::cout << "data[\"user\"][\"id\"] = " << client.subscription.user.id << "\n";
    return 0;
}
