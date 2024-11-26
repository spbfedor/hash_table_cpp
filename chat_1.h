#pragma once

#include "sha_1.h"
#include <string.h>

#define SIZE 20
#define LOGINLENGTH 20

class Chat {
    public:
        Chat();
        ~Chat();
        void reg(char _login[LOGINLENGTH], char _pass[], int pass_length);
        bool login(char _login[LOGINLENGTH], char _pass[], int pass_length);
        
    private:
        enum enAuthDataStatus {
            free,
            engaged,
            deleted
        };
        struct AuthData {
            AuthData(): 
                login(""),
                pass_sha1_hash(0),
                status(enAuthDataStatus::free) {
            }
            ~AuthData() {
                if(pass_sha1_hash != 0 )
                    delete [] pass_sha1_hash;
            }
            AuthData(char _login[LOGINLENGTH], uint* sh1): 
                pass_sha1_hash(sh1),
                status(enAuthDataStatus::engaged) {
                    strcpy(login, _login);
                }
            AuthData& operator = (const AuthData& other) {
                strcpy(login, other.login);
                status = other.status;
                
                if(pass_sha1_hash != 0)
                    delete [] pass_sha1_hash;
                pass_sha1_hash = new uint[SHA1HASHLENGTHUINTS];
                
                memcpy(pass_sha1_hash, other.pass_sha1_hash, SHA1HASHLENGTHBYTES);
                
                return *this;
            }           
            char login[LOGINLENGTH];
            uint* pass_sha1_hash;
            enAuthDataStatus status;
        };
        
        int hash_func_mult(int value);
        int hash_func(char login[LOGINLENGTH], int offset);
        void add(char login[LOGINLENGTH], uint* digest);
        void resize();
        AuthData* data;
        int mem_size;
        int data_count;
};
