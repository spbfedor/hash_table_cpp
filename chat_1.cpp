#include "../headers/chat_1.h"
#include "../headers/sha_1.h"
#include <iostream>
#include <string.h>

Chat::Chat() {
    data_count = 0;
    data = new AuthData[mem_size];

    mem_size = 8;
}

Chat::~Chat() {
    delete[] data;
}
void Chat::reg(char _login[LOGINLENGTH], char _pass[], int pass_length) {
    // Ваш код
    uint* digest = sha1(_pass, pass_length);
    add(_login, digest);
}

bool Chat::login(char _login[LOGINLENGTH], char _pass[], int pass_length) {
    // Ваш код
    // Нужно вернуть true в случае успешного логина
    int i = 0;
    for(; i<data_count; i++) {
        AuthData& ad = data[i];
        if (!strcmp(ad.login, _login)) {
            break;
        }
    }
    if(i >= data_count) return false;
    
    uint* digest = sha1(_pass, pass_length);
    
    bool cmpHashes = !memcmp(
                        data[i].pass_sha1_hash, 
                        digest, 
                        SHA1HASHLENGTHBYTES);
    delete[] digest;
    
    return cmpHashes;
}

void Chat::add(char login[LOGINLENGTH], uint* digest) {
    int index, i = 0;
    for (; i < mem_size; i++) {
        index = hash_func(login, i * i);
        if (data[index].status == enAuthDataStatus::free)
            break;
    }
    if (i >= mem_size)
    {
        resize();
        add(login, digest);
    }
    else {
        data[index] = AuthData(login, digest);
        data_count++;
    }
}

void Chat::resize() {
    AuthData* old_data = data;
    int old_mem = mem_size;
    mem_size *= 2;
    data = new AuthData[mem_size];
    data_count = 0;

    for (int i = 0; i < old_mem; i++) {
        AuthData& od = old_data[i];
        if (od.status == enAuthDataStatus::engaged) {

            uint* sha_hash_copy = new uint[SHA1HASHLENGTHUINTS];
            memcpy(sha_hash_copy, od.pass_sha1_hash, SHA1HASHLENGTHBYTES);

            add(od.login, sha_hash_copy);
        }
    }

    delete[] old_data;
}

int Chat::hash_func_mult(int value) {
    const double A = 0.7;
    return int(mem_size * (A * value - int(A * value)));
}

int Chat::hash_func(char login[LOGINLENGTH], int offset) {
    long sum = 0;
    for (int i = 0; i < LOGINLENGTH; i++) {
        sum += login[i];
    }
    return (hash_func_mult(sum) + offset) % mem_size;
}