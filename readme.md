## Windows

TBD

## Mac and Linux

#### Install prerequisites:

Mac:

```sh
brew install openssl
```

Linux:

```sh
apt install openssl
apt install libssl-dev
```

### Build app (using GCC / G++)

```sh
g++ src/main.cpp -o build/main -I /opt/homebrew/Cellar/openssl@3/3.3.0/include -L /opt/homebrew/Cellar/openssl@3/3.3.0/lib -lcurl -lcrypto -std=c++11
```

These linked file locations may be different depending on how you installed OpenSSL & CURL, so use them accordingly.
