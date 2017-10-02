/*
 * CryptoAlgos.h
 *
 *      Author: Francesco Boi
 */

#ifndef CRYPTOALGOS_H_
#define CRYPTOALGOS_H_
#include <iostream>
#include <vector>
#include <gmp.h>
#include <crypto++/hex.h>
#include <gmpxx.h>

//The function tries to decrypt the string 'target' assuming that the target and
// the strings in the vector are encrypted with the OTP algo using the same key.
//The strings are passed as hex strings
std::string attackOTP2(std::vector<std::string> vect, std::string target);


//The function decrypts with the CTR-AES algo
std::string ctr_AesDecrypt(std::string ct, std::string s_key);

//The function decrypts with the CBC-AES algo
std::string cbc_AesDecrypt(std::string ct, std::string s_key);

//The function encrypts with the ctr-AES algo.
std::string ctr_AesEncrypt(std::string ct, std::string s_key, std::string randIV);

//The function encrypts with the cbc-AES algo.
std::string cbc_AesEncrypt(std::string ct, std::string s_key, std::string randIV);

bool cbc_test(std::string ct, std::string pt, std::string s_key);

bool ctr_test(std::string ct, std::string pt, std::string s_key);

//The functon calculates the hash values for a file divided into 1KB blocks in reverse order
byte* CalculateHash2(std::string fpath, unsigned int blocksize);

// The function computes log modulo a prime p
void DHLog(mpz_t p, mpz_t g, mpz_t h, unsigned int max_exp);

std::vector<mpz_class> defactor_p_q_close(mpz_class N);

//Returns the prob of a number being prime
unsigned int is_prime(mpz_t p);
#endif /* CRYPTOALGOS_H_ */

