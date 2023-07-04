#include "manager.h"

bool Manager::ip_isvalid(const std::string& ip) {
    int points = 0;
    int len = ip.length();
    std::string digits = "\n";

    int i;
    for(i = 0; i < len; i++) {
        char ch = ip[i];

        if((ch != '.') && ((ch < '0') || ('9' < ch))) {
            std::cerr << "\nIp is not numeric or '.'\n";
            return false;
        }

        if(ch != '.') digits += ch;
        else {
            if(std::stoi(digits) > 255) {
                std::cerr << "\nIp isn't in the form: [0-255].[0-255].[0-255].[0-255]\n";
                return false;
            }

            digits = "";
            points++;
        }
    }

    if((points != 3) || (std::stoi(digits) > 255)) {
        std::cerr << "\nIp isn't in the form: [0-255].[0-255].[0-255].[0-255]\n";
        return false;
    }

    return true;
}

bool Manager::ip_valid(const std::string& ip) {
    return ip_isvalid(ip);
}

std::string Manager::random(int bytes) {
    char trash[bytes + 1]; //memory trash
    trash[bytes] = '\0';
    return sdes.encode(std::string(trash),S_DES::CBC);
}

bool Manager::start_server() {
    if(local_server_socket != -1)
        close(local_server_socket);

    local_server_socket = socket(AF_INET, SOCK_STREAM, 0);

    if(local_server_socket == -1) {
        std::cerr << "\nFailed to create socket." << std::endl;
        return false;
    }

    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;

    if(setsockopt(local_server_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        std::cerr << "\nFailed to set receive timeout\n" << std::endl;
        close(local_server_socket);
        return 0;
    }

    sockaddr_in local_server{};
    local_server.sin_family = AF_INET;
    local_server.sin_addr.s_addr = INADDR_ANY;
    local_server.sin_port = htons(3000);

    if(bind(local_server_socket, (struct sockaddr*)&local_server, sizeof(local_server)) == -1) {
        std::cerr << "\nFailed to bind socket.\n" << std::endl;
        close(local_server_socket);
        return false;
    }

    if(listen(local_server_socket, 5) == -1) {
        std::cerr << "\nFailed to listen for connections." << std::endl;
        close(local_server_socket);
        return false;
    }

    return true;
}

int Manager::getSharedKey() {
    return sharedKey;
}

Manager::Manager() {
    destination.sin_family = AF_INET;
    destination.sin_port = htons(3000);
    local_server_socket = -1;

    int prime = 12;
    int generator = 18;
    int privateKey = 22;

    dh.set_DH(prime, generator, privateKey);
    publicKey = dh.PublicKey();
}

Manager::~Manager() {
    if(local_server_socket != -1)
        close(local_server_socket);
}

bool Manager::set_ip(const std::string& ip) {
    if(!ip_isvalid(ip)) return false;

    destination.sin_addr.s_addr = inet_addr(ip.c_str());
    return true;
}

bool Manager::set_key(const std::string& key, Manager::encoding choice) {
    switch(choice) {
        case Rc4:
            rc4.update(key);
        break;
        case Sdes:
            try {
                int int_key = std::stoi(key);
                if(int_key > ((1 << 11) - 1)) {
                    std::cerr << "\nSDES key is too big.\n";
                    return false;
                }
                sdes.update(int_key);
            } catch(...) {
                std::cerr << "\nSDES key should be numeric\n";
                return false;
            }
        break;
    }

    return true;
}

bool Manager::dispatch(const std::string& plain, Manager::encoding choice, Manager::smode mode) {
    if(plain.size() > 4096) {
        std::cerr << "\nThe message is too long.\n" << std::endl;
        return false;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1) {
        std::cerr << "\nFailed to create socket.\n" << std::endl;
        return false;
    }

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    if(setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout)) < 0) {
        std::cerr << "\nFailed to set send timeout\n" << std::endl;
        close(sockfd);
        return 0;
    }

    if(connect(sockfd, (struct sockaddr*)&destination, sizeof(destination)) == -1) {
        std::cerr << "\nFailed to connect to the server.\n" << std::endl;
        close(sockfd);
        return false;
    }

    std::string cipher;
    switch(choice) {
        case Sdes:
            cipher = sdes.encode(plain, (S_DES::mode)mode);
        break;
        case Rc4:
            cipher = rc4.encode(plain);
        break;
        case Dh:
            send(local_server_socket, std::to_string(publicKey).c_str(), std::to_string(publicKey).size(), 0);

            char publicKeyBuffer[4096];

            bool status = false;
            std::string key;
            std::string client_ip = "0";

            char destination_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET,&(destination.sin_addr),destination_ip,INET_ADDRSTRLEN);
            std::string destination_str(destination_ip);

            while(client_ip != destination_str)
                std::tie(status,key,client_ip) = receive(Dh,Manager::CBC);

            int destPublicKey = std::stoi(key);
            sharedKey = dh.SharedKey(destPublicKey);
            return true;

    }

    int status = send(sockfd, cipher.c_str(), cipher.size(), 0);
    close(sockfd);
    if(status == -1) {
        std::cerr << "\nFailed to send data to the server.\n" << std::endl;
        return false;
    }

    return true;
}

std::tuple<bool, std::string, std::string> Manager::receive(Manager::encoding choice, Manager::smode mode) {
    sockaddr_in client{};
    socklen_t client_size = sizeof(client);

    int client_socket = accept(local_server_socket, (struct sockaddr*)&client, &client_size);
    if(client_socket == -1) {
        return std::make_tuple(false, "", "");
    }

    char cipher_buffer[4096];
    ssize_t cipher_size = read(client_socket, cipher_buffer, sizeof(cipher_buffer));

    if(cipher_size == -1) {
        std::cerr << "Error reading data from client." << std::endl;
        return std::make_tuple(false, "", "");
    }

    if(cipher_size == 0) {
        return std::make_tuple(false, "", "");
    }

    close(client_socket);

    char client_ip[INET_ADDRSTRLEN];
    memset(client_ip, 0, sizeof(client_ip));
    inet_ntop(AF_INET, &(client.sin_addr), client_ip, INET_ADDRSTRLEN);

    std::string cipher(cipher_buffer, cipher_size);
    switch(choice) {
        case Sdes:
            return std::make_tuple(true, sdes.decode(cipher, (S_DES::mode)mode), std::string(client_ip));
        break;
        case Rc4:
            return std::make_tuple(true, rc4.encode(cipher), std::string(client_ip));
        break;
        case Dh:
            return std::make_tuple(true, cipher, std::string(client_ip));
            break;
        default:
            return std::make_tuple(false, "", "");
        break;

    }
}
