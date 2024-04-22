#include "../include/tsar/client.hpp"
#include <iostream>

int main()
{
    std::string appId = "58816206-b24c-41d4-a594-8500746a78ee";
    std::string publicKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELlyGTmNEv3AarudyshJUUA9ig1pOfSl5qWX8g/hkPiieeKlWvv9o4IZmWI4cCrcR0fteVEcUhBvu5GAr/ITBqA==";

    Client client(appId, publicKey);

    std::cout << "data[\"user\"][\"id\"] = " << client.subscription.user.id << "\n";
    return 0;
}
