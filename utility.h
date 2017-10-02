/*
 * utility
 *
 *      Author: Francesco Boi
 */

#ifndef UTILITY_H_
#define UTILITY_H_

#include<vector>

//The function compute the XOR bwtween two strings of arbitrary length.
std::string operator^(const std::string& a,
                      const std::string& b);

//The function checks if the character is a capital letter
bool checkCapitalLetter(char c);

//The function calculates the maximum length of the strings in the vector
unsigned int CalcmaxStringSize(std::vector<std::string> myvect);

//The function prints the decoded string
void printDecodedStrings(std::vector<std::string> vec, std::string k);

//The function print the string using proper interspaces
void printInterspacedString(std::string ss);

//Converts the string to lower chars
std::string toLower(std::string in);

//The function converts a string to its hex representation
std::string hexStr(unsigned char *data, int len);

std::string toFormatFromDecimal(mpz_class t);

#endif
