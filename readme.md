## Windows

To be done & tested

## Mac and Linux

### Install OpenSSL (if it isnt already installed):

Mac:

```
brew install openssl
```

Linux:

```
apt install openssl
apt install libssl-dev
```

```
apt install libssl-dev
```

### Build app (using GCC / G++)

```
g++ src/main.cpp -o build/main -I /opt/homebrew/Cellar/openssl@3/3.3.0/include -L /opt/homebrew/Cellar/openssl@3/3.3.0/lib -lcurl -lcrypto -std=c++11
```

These linked file locations may be different depending on how you installed OpenSSL, so use them accordingly.
