/*
 * utility.cpp
 *
 *      Author: Francesco Boi
 */

#include <algorithm>
#include <iostream>
#include <boost/algorithm/hex.hpp>
#include <vector>
#include <gmpxx.h>

static const char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};    

//The function compute the XOR bwtween two strings of arbitrary length.
std::string operator^(const std::string& a,
                      const std::string& b)
{
  std::string r(a);
  std::transform(a.begin(), a.end(),
                 b.begin(),
                 r.begin(),
                 [](char a_, char b_) {
                   return a_ ^ b_;
  	  	  	  	  });
  return r;
}


//The function checks if the character is a capital letter
bool checkCapitalLetter(char c)
{
	bool res = false;
	if (c>64 && c<91)
	{
		res = true;
	}
	return res;
}

//The function calculates the maximum length of the strings in the vector
unsigned int CalcmaxStringSize(std::vector<std::string> myvect)
{
	unsigned int res = 0,ii ;
	for (ii=0; ii<myvect.size(); ii++)
	{
		res = res>myvect.at(ii).length() ? res : myvect.at(ii).length();
	}
	return res;

}

//The function prints the decoded string
void printDecodedStrings(std::vector<std::string> vec, std::string k)
{
	unsigned int ii;
	for (ii=0; ii<vec.size(); ii++)
	{
		std::string decoded = boost::algorithm::unhex(vec.at(ii))^ k;
		std::cout<<ii<<") "<<decoded<<std::endl;
	}

}

//The function print the string using proper interspaces.
void printInterspacedString(std::string ss)
{
	unsigned int ii;
	std::stringstream strs;
	std::string t, pos_str;
	strs <<ss[0];
	std::cout<<strs.str()<<std::endl;
	for (ii=1; ii<ss.size(); ii++)
	{
		strs << ' '<<' '<<' ' << ss[ii];
		char temp2[10];
		if (ii<10)
		{
			pos_str +=  std::string(temp2)+ "   ";
		}
		else if (ii<100)
		{
			pos_str +=  std::string(temp2)+ "  ";
		}
		else
		{
			pos_str +=  std::string(temp2)+ " ";
		}

	}
	std::cout<<strs.str()<<std::endl;
	std::cout<<pos_str<<std::endl;

}

//Converts the string to lower chars
std::string toLower(std::string in)
{
	std::string res = "";
	unsigned int ii;
	for (ii=0; ii<in.size(); ii++)
	{
		res+= tolower(in.at(ii));
	}
	return res;
}

//The function converts a string to its hex representation
std::string hexStr(unsigned char *data, int len)
{

  std::string s(len * 2, ' ');
  for (int i = 0; i < len; ++i) {
    s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
    s[2 * i + 1] = hexmap[data[i] & 0x0F];
  }
  return s;
}


std::string toFormatFromDecimal(mpz_class t) {

	std::string res = "";
    mpz_t temp;
    mpz_init_set_ui(temp, 0);
    unsigned int pos;
    do {
        pos = mpz_mod_ui(temp, t.get_mpz_t(), 16);
        res = res+hexmap[pos] ;
        t = t/16;

    } while ((mpz_cmp_ui(t.get_mpz_t(), 0) != 0));

    return std::string(res.rbegin(), res.rend());
}