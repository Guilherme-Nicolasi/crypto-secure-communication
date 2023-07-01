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

        bool ip_isvalid(const std::string& ip);

    public:
        bool ip_valid(const std::string& ip);
        bool start_server();
        Manager();
        ~Manager();
        enum encoding {
            Sdes,
            Rc4
        };
        enum smode {
            ECB = S_DES::ECB,
            CBC = S_DES::CBC
        };
        bool set_ip(const std::string& ip);
        bool set_key(const std::string& key, encoding choice);
        bool dispatch(const std::string& plain, encoding choice, smode mode);
        std::tuple<bool, std::string, std::string> receive(encoding choice, smode mode);
};

#endif // MANAGER_H
