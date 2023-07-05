#ifndef MANAGER_H
#define MANAGER_H

#include <iostream>
#include <string>
#include <tuple>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include "sdes.h"
#include "rc4.h"
#include "dh.h"

class Manager {
    private:
        int local_server_socket;
        sockaddr_in destination;
        S_DES sdes;
        RC4 rc4;
        int sharedKey;
        int publicKey;
        DH dh;

        bool ip_isvalid(const std::string& ip);

    public:
        bool ip_valid(const std::string& ip);
        std::string random(int bytes);
        int getSharedKey();
        bool start_server();
        Manager();
        ~Manager();
        enum encoding {
            Sdes_ECB,
            Sdes_CBC,
            Rc4,
            None
        };
        bool set_ip(const std::string& ip);
        bool set_key(const std::string& key, encoding choice);
        bool dispatch(const std::string& plain, encoding choice);
        bool key_exchange();
        std::tuple<bool, std::string, std::string> receive(encoding choice);
};

#endif // MANAGER_H
