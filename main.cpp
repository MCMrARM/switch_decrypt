#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <vector>
#include <cassert>
#include "hex_string.h"
#include "xts_crypto.h"

int main(int argc, char* argv[]) {
    if (argc < 7) {
        printf("switch_decrypt <source> <destination> <offset> <size> <key_crypto> <key_tweak>\n");
        return 1;
    }

    std::vector<unsigned char> key_crypto = hex_string::decode(argv[5]);
    std::vector<unsigned char> key_tweak = hex_string::decode(argv[6]);

    int in_fd = open(argv[1], O_RDONLY);
    int out_fd = open(argv[2], O_WRONLY | O_CREAT, 0644);

    char* endp;
    long int offset = std::strtol(argv[3], &endp, 0);
    assert(endp != nullptr);
    long int size = std::strtol(argv[4], &endp, 0);
    assert(endp != nullptr);

    size_t sector_size = 0x4000;
    xts_crypto crypto (key_crypto.data(), key_tweak.data(), sector_size);
    unsigned char buf[sector_size];
    lseek(in_fd, offset, SEEK_SET);
    for (size_t i = 0; i < size / sector_size; i++) {
        if ((i % 1024) == 0)
            printf("%li / %li\n", i, size / sector_size);
        if (read(in_fd, buf, sector_size) < sector_size)
            throw std::runtime_error("Read failed");
        crypto.decrypt(buf, i);
        if (write(out_fd, buf, sector_size) < sector_size)
            throw std::runtime_error("Write failed");
    }

    close(in_fd);
    close(out_fd);
    return 0;
}