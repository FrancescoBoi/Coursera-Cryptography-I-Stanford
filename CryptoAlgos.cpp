/*
 * CryptoAlgos.cpp
 *
 *      Author: Francesco Boi
 */

#include <iostream>
#include <CryptoAlgos.h>
#include <utility.h>
#include <boost/algorithm/hex.hpp>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/sha.h>
#include<fstream>
#include <gmp.h>
#include <gmpxx.h>
//#include <aes.h>
//#include <modes.h>


//The function tries to decrypt the string 'target' assuming that the target and
// the strings in the vector are encrypted with the OTP algo using the same key.
//The strings are passed as hex strings
std::string attackOTP2(std::vector<std::string> vect, std::string target)
{
	std::vector<std::string> loc_vect(vect);
	loc_vect.insert(loc_vect.end(), target);
	std::string xored, key = "";
	unsigned int maxStringSize = CalcmaxStringSize(loc_vect)/2;
	while (key.size() < maxStringSize)
	{
		key += "_";
	}
	unsigned int counter[loc_vect.size()][maxStringSize] = {0};
	unsigned char ii=0, jj=0, kk=0;
	for (unsigned int ll=0; ll<loc_vect.size(); ll++)
	{
		std::cout<<std::endl;
		for(unsigned int tt=0; tt<maxStringSize; tt++)
			counter[ll][tt] =0;
	}
	for (ii=0; ii<vect.size(); ii++)
	{

		//XOR the strings
		for (jj=1; jj<vect.size()+ii; jj++)
		{
			//std::cout<<(ii+jj)%loc_vect.size();
			xored = boost::algorithm::unhex(loc_vect.at(ii)) ^
					boost::algorithm::unhex(loc_vect.at((ii+jj)%loc_vect.size()));
			//written english is the space: xoring a letter with the space results in capital letter.
			for (kk = 0; kk < xored.size(); kk++)
			{
				if (checkCapitalLetter(xored[kk]))
				{
					counter[ii][kk]++;
				}
			}
		}


	}
	//now we look for the max in the histogram the most frequent value in

	unsigned int max_val =0;
	char c;
	for (jj=0; jj<key.size(); jj++)
	{
		max_val = 0;
		for (ii=0; ii< loc_vect.size(); ii++)
		{
			if(max_val < counter[ii][jj] && jj<boost::algorithm::unhex(loc_vect.at(ii)).length())
			{
				max_val = counter[ii][jj];

				c = ' ' ^ boost::algorithm::unhex(loc_vect.at(ii)).at(jj);
				std::stringstream ss;
				ss<<c;
				std::string t;
				ss>>t;;
				key.replace( jj, 1, t);
			}
		}
	}
	std::string res = key^boost::algorithm::unhex(target);
	std::cout<<res;
	printDecodedStrings(loc_vect, key);
	c =' ';
	std::string pos_str;
	ii=0;

	std::string in = "a", in2,corrected_string, char_pos;
	unsigned char corr_type = 100;
	unsigned int str_selected, char_corr;

	//Allow the user to performs changes
	while(1)
	{
		str_selected = loc_vect.size();
		while(str_selected>loc_vect.size()-1)
		{

			std::cout<<"\nPress the number of the string to be corrected or "
					"q quit\n";
			std::getline(std::cin,in);
			str_selected = std::atoi(in.c_str());
		}

		if (in.compare("q")==0)
		{
			break;
		}
		corr_type = 10;
		while(corr_type!=1 && corr_type !=2)
		{
			std::cout<<"Press 1 to correct the entire string, "
					"2 to correct a single char\n";
			std::getline(std::cin,in2);

			corr_type = std::atoi(in2.c_str());
		}
		switch(corr_type){
		case 1:
			{
				std::cout<<"enter the correction string\n";
				std::getline(std::cin,corrected_string);
				std::cin.clear();

				key.replace(0, corrected_string.size() ,
						corrected_string ^ boost::algorithm::unhex(loc_vect.at(str_selected)));
				break;
			}
		case 2:
		{

			char_corr = loc_vect.at(str_selected).size()+1;
			while (	char_corr>loc_vect.at(str_selected).size()/2+1)
			{
				printInterspacedString(boost::algorithm::unhex(loc_vect.at(str_selected)) ^ key);
				std::cout<<"enter the position of the char to be changed\n";
				std::getline(std::cin,char_pos);//using it again to avoid new decl
				char_corr = std::atoi(char_pos.c_str());

			}
			std::cout<<"enter the substituition value\n";
			std::getline(std::cin,char_pos);
			key.replace(char_corr-1, 1,
				boost::algorithm::unhex(
						loc_vect.at(str_selected)).substr(char_corr-1,1)
					^ char_pos.substr(0,1));
			break;
		}
		default:
			break;
		}
		printDecodedStrings(loc_vect, key);
	}
	//6-th string decr There are two types of cyptography: one that allows the Government to use brute force to break the code, and one that requires the Government to use brute force to break
	return key;
}

//The function decrypts with the CBC-AES algo
std::string cbc_AesDecrypt(std::string ct, std::string s_key)
{
	unsigned int ii=0;
	unsigned char pad_size=0;
	std::string decrypted, temp;
	unsigned char result[CryptoPP::AES::BLOCKSIZE] = {'\0'};
	CryptoPP::SecByteBlock Key_cbc((unsigned char*)s_key.c_str(),
			CryptoPP::AES::BLOCKSIZE);
	CryptoPP::AESDecryption aesDec_cbc(Key_cbc);
	for(ii = 1; ii< ct.size()/16; ii++)
	{
		std::memcpy(result, ct.substr(ii*16,16).c_str(),
				CryptoPP::AES::BLOCKSIZE);
		aesDec_cbc.ProcessBlock(result);
		//m[i] = c[i-1] XOR D[k,c[i]]
		temp = ct.substr((ii-1)*16, 16) ^ std::string((const char*)result);
		decrypted.append(temp);
	}
	pad_size = decrypted.at(decrypted.size()-1);
	return decrypted.substr(0, decrypted.size()-pad_size);
}

//The function decrypts with the CTR-AES algo
std::string ctr_AesDecrypt(std::string ct, std::string s_key)
{
	unsigned int ii;
	unsigned char result[CryptoPP::AES::BLOCKSIZE] = {'\0'};
	unsigned char in[CryptoPP::AES::BLOCKSIZE] = {'\0'};

	std::string temp, decrypted;
	CryptoPP::SecByteBlock key_ctr((unsigned char*) s_key.c_str(),
			CryptoPP::AES::BLOCKSIZE);
	CryptoPP::AESEncryption aesDec_ctr(key_ctr);
	std::memcpy(in, ct.substr(0,16).c_str(),
					CryptoPP::AES::BLOCKSIZE);
	for(ii = 1; ii<= ct.size()/16; ii++)
	{
		in[15]+=(ii>1);
		aesDec_ctr.ProcessBlock(in, result);

		temp = ct.substr(ii*16, 16) ^ std::string((const char*)result);
		decrypted.append(temp);
	}
	return decrypted;
}

//The function encrypts with the CBC-AES algo
std::string cbc_AesEncrypt(std::string pt, std::string s_key, std::string randIV)
{
	std::string encrypted, temp, paddedStr;
	unsigned int ii = 0;
	unsigned char result[CryptoPP::AES::BLOCKSIZE] = {'\0'};
	unsigned char padEl = CryptoPP::AES::BLOCKSIZE - pt.size()%CryptoPP::AES::BLOCKSIZE;
	CryptoPP::SecByteBlock Key_cbc((unsigned char*)s_key.c_str(),
			CryptoPP::AES::BLOCKSIZE);
	CryptoPP::AESEncryption aesEnc_cbc(Key_cbc);
	encrypted.append(randIV);
	std::memcpy(result, randIV.c_str(),CryptoPP::AES::BLOCKSIZE);
	paddedStr.append(pt);
	paddedStr.append(padEl, static_cast<char>(padEl));
	//n blocks of 16 bytes + 1 block (if not multiple of 16) + a block for padding
	for(ii = 0; ii< paddedStr.size()/CryptoPP::AES::BLOCKSIZE; ii++)
	{
		std::string tt = boost::algorithm::hex(paddedStr.substr((ii*(CryptoPP::AES::BLOCKSIZE)),
				CryptoPP::AES::BLOCKSIZE));

		temp = paddedStr.substr((ii*(CryptoPP::AES::BLOCKSIZE)),CryptoPP::AES::BLOCKSIZE) ^
				encrypted.substr(ii*CryptoPP::AES::BLOCKSIZE, CryptoPP::AES::BLOCKSIZE);

		memcpy(result, temp.c_str(), CryptoPP::AES::BLOCKSIZE);

		aesEnc_cbc.ProcessBlock(result);

		std::string toBeAppended((const char*)(result), CryptoPP::AES::BLOCKSIZE);
		encrypted.append(toBeAppended);
	}
	return encrypted;
}


//The function encrypts with the CTR-AES algo
std::string ctr_AesEncrypt(std::string pt, std::string s_key, std::string randIV)
{
	std::string encrypted;
	unsigned int ii;
	unsigned char result[CryptoPP::AES::BLOCKSIZE] = {'\0'};
	unsigned char in[CryptoPP::AES::BLOCKSIZE] = {'\0'};
	CryptoPP::SecByteBlock Key_cbc((unsigned char*)s_key.c_str(),
			CryptoPP::AES::BLOCKSIZE);
	CryptoPP::AESEncryption aesEnc_cbc(Key_cbc);
	encrypted.append(randIV);
	memcpy(in, encrypted.substr(0, CryptoPP::AES::BLOCKSIZE).c_str(), CryptoPP::AES::BLOCKSIZE);
	for (ii=0; ii<pt.size()/CryptoPP::AES::BLOCKSIZE + ((pt.size()%CryptoPP::AES::BLOCKSIZE)!=0); ii++)
	{
		in[15]+= ii>0;
		aesEnc_cbc.ProcessBlock(in, result);
		encrypted.append((pt.substr(ii*16, 16) ^ std::string((const char*)result)));
	}
	return encrypted;
}


bool cbc_test(std::string ct, std::string pt, std::string s_key)
{
	//TEST
	std::string reEncrypted = cbc_AesEncrypt( cbc_AesDecrypt(ct, s_key),
		s_key,
		ct.substr(0,16) );
	reEncrypted = boost::algorithm::hex(reEncrypted);
	reEncrypted = toLower(reEncrypted);
	std::cout<<"CBC test\n";
    std::cout<<boost::algorithm::hex(ct)<<std::endl;
	std::cout<<reEncrypted<<std::endl;
	return (reEncrypted.compare(ct) == 0);
}


bool ctr_test(std::string ct, std::string pt, std::string s_key)
{
	//TEST
	std::string reEncrypted = ctr_AesEncrypt( ctr_AesDecrypt(ct, s_key),
		s_key,
		ct.substr(0,16) );
	reEncrypted = boost::algorithm::hex(reEncrypted);
	reEncrypted = toLower(reEncrypted);
    std::cout<<"CTR test\n";
	std::cout<<boost::algorithm::hex(ct)<<std::endl;
	std::cout<<reEncrypted<<std::endl;
	return (reEncrypted.compare(ct) == 0);
}

//The functon calculates the hash values for a file divided into 1KB blocks in reverse order
byte* CalculateHash2(std::string fpath, unsigned int blocksize)
{
	char buff[blocksize];
	unsigned int augmentedBlockSize = blocksize + 32;
	unsigned int size, residual;
	unsigned char augmentedBlock[augmentedBlockSize];

	std::ifstream fs;//, fvector;
	std::ofstream fout, fout2, fout3;
	std::string vectorPath = "vector0.txt";
	//fout.open("/home/bigmac/Desktop/temp.txt", ios::out);
	fout2.open("vector1.txt", std::ios::out);
	fout3.open(vectorPath.data(), std::ios::out);
	byte digest[CryptoPP::SHA256::DIGESTSIZE];
	fs.open(fpath.data(), std::ios::in | std::ios::binary|std::ios::ate);
	size = fs.tellg();

	residual = size%blocksize;
	char buff_res[residual];
	fs.seekg (size-residual);
	fs.read(buff_res, residual);
	CryptoPP::SHA256().CalculateDigest(digest,
			reinterpret_cast<unsigned char*>(buff_res), residual);
 
    std::string finalOut;
	fs.seekg (size-residual);
	unsigned int ii = 0;
	if (fs.is_open())
	{
		while((ii)*blocksize<size)
		{
			std::string output;
			CryptoPP::HexEncoder encoder, enc2;
			encoder.Attach( new CryptoPP::StringSink( output ) );
			encoder.Put( digest, sizeof(digest) );
			encoder.MessageEnd();
			std::transform(output.begin(), output.end(), output.begin(), ::tolower);
			finalOut = output;//std::cout << output << std::endl;
			//3d iter 8c0bad3303518f7f40de7547b532f6fe92eb6b6a9d31f955b71e1afe14eb60c9
			fs.seekg(size-residual-blocksize*(ii+1));
			fs.read(buff, blocksize);
			memcpy(augmentedBlock, buff, blocksize);
			memcpy(&augmentedBlock[blocksize], digest, 32);
					CryptoPP::SHA256().CalculateDigest(digest, augmentedBlock, augmentedBlockSize);

			ii++;
		}
		fs.read(buff_res, residual);
	}
    std::cout<<finalOut<<std::endl;
	fout3.close();
	fs.close();
	fout2.close();

	return digest;
}

// The function computes log modulo a prime p
void DHLog(mpz_t p, mpz_t g, mpz_t h, unsigned int max_exp)
{
	unsigned int maxsize=pow(2,max_exp/2);
	mpz_t res;
	unsigned long val = 0;
	mpz_init_set_ui(res,val);
	mpz_t x0, x1;
	mpz_init_set_ui(x0, 0);
	mpz_init_set_ui(x1, 0);
	mpz_t b,g_b;

	mpz_t base_2, exp_20;
	mpz_init_set_ui(base_2, 2);
	mpz_init_set_ui(exp_20, max_exp/2);
	mpz_init(b);
	mpz_powm_sec(b, base_2, exp_20, p);
	gmp_printf("2^20 = %Zd\n", b);
	mpz_t exponent;
	mpz_init_set_ui(exponent, 0);
	gmp_printf("p = %Zd\n", p);
	gmp_printf("g = %Zd\n", g);
	gmp_printf("h = %Zd\n", h);

	mpz_t* hash_t;
	hash_t = (mpz_t *) malloc(maxsize * sizeof(mpz_t));
	unsigned int ii=0, jj=0;

	//gmp_printf("%Zd\n", p);
	for(ii=0; ii<maxsize;ii++)
	{
		mpz_init_set_ui(hash_t[ii], 0);
		mpz_t temp;
		mpz_init_set_ui(temp,0);
		mpz_init_set_d(exponent, ii);
		//gmp_printf("exp = %Zd\n", exponent);

		mpz_powm(temp, g, exponent, p);
		//gmp_printf("g^exp = %Zd\n", temp);
		//int r = mpz_invert(temp,temp, p);
		//gmp_printf("inverse = %Zd\n", temp);

		mpz_mul(temp, temp, h);
		//gmp_printf("g^exp *h = %Zd\n", temp);
		mpz_mod(hash_t[ii], temp, p);
		//gmp_printf("%Zd\n\n", hash_t[ii]);
	}
	mpz_init_set_ui(g_b, 0);
	mpz_powm(g_b, g, b, p);
	bool found = false;
	for(ii=0; ii<maxsize;ii++)
	{
		//calculate (g^b)^x0
		mpz_t candidate;
		mpz_init_set_ui(candidate, 0);
		mpz_init_set_ui(x0, ii);
		mpz_powm(candidate, g_b, x0, p);
		if (ii%1000 ==0)
		{
			printf("analysed: %d\n", ii);
		}

		for (jj=0; jj<maxsize;jj++)
		{

			if (mpz_cmp(candidate, hash_t[jj]) == 0)
			{
				gmp_printf("x0 = %Zd\n", x0);
				printf("x1 = %d\n", jj);
				mpz_init_set_ui(x1, jj);
				found = true;
				break;
			}
		}
		if (found)
		{
			break;
		}
	}
	printf("finished\n");

	//x = x0*B + x1
	mpz_mul(res, x0, b);
	mpz_mod(res, res, p);
	mpz_add(res, res,x1);
	mpz_mod(res,res,p);
	gmp_printf("x = %Zd\n", res);
	gmp_printf("h = %Zd\n", h);
	gmp_printf("g = %Zd\n", g);
	mpz_t verify;
	mpz_init_set_ui(verify, 0);
	mpz_powm_sec(verify, g, res,p);
	gmp_printf("g^x = h = %Zd\n", verify);

}


std::vector<mpz_class> defactor_p_q_close(mpz_class N)
{
	/*
	 * Normally, the primes that comprise an RSA modulus are generated independently of one another.
	 * But suppose a developer decides to generate the first prime p by choosing a random number R and
	 * scanning for a prime close by. The second prime q is generated by scanning for some other random
	 * prime also close to R.
	 * We show that the resulting RSA modulus N=pq can be easily factored.
	 * Suppose you are given a composite N and are told that N is a product of two relatively close primes
	 * p and q, namely p and q satisfy
	 * |p−q|<2N^(1/4) (*)
	 * Your goal is to factor N.
	 * Let A be the arithmetic average of the two primes, that is A=p+q2. Since p and q are odd, we know
	 * that p+q is even and therefore A is an integer.
	 * To factor N you first observe that under condition (*) the quantity N‾‾√ is very close to A.
	 * In particular, we show below that:
	 * A−sqrt(N)<1
	 * But since A is an integer, rounding N‾‾√ up to the closest integer reveals the value of A. In code,
	 *  A=ceil(sqrt(N)) where "ceil" is the ceiling function.
	 * Since A is the exact mid-point between p and q there is an integer x such that p=A−x and q=A+x.
	 * But then N=pq=(A−x)(A+x)=A^2−x^2 and therefore x=sqrt(A^2−N).
	 * Now, given x and A you can find the factors p and q of N since p=A−x and q=A+x. */
	std::vector<mpz_class> res;
	mpz_class A, x,p,q, check,t;
		mpz_t N2, A2, temp2, x2, p2, q2;
		mpz_init(N2);
		mpz_init_set_ui(A2, 0);
		mpz_init_set_ui(temp2, 0);
		mpz_init_set_ui(x2, 0);
		mpz_init_set_ui(p2, 0);
		mpz_init_set_ui(q2, 0);
		/*mpz_set_str(N2,"17976931348623159077293051907890247336179769789423065727343008115"
				"77326758055056206869853794492129829595855013875371640157101398586"
				"47833778606925583497541085196591615128057575940752635007475935288"
				"71082364994994077189561705436114947486504671101510156394068052754"
				"0071584560878577663743040086340742855278549092581",10);*/

		//sqrt approximates to the smallest integer : sqrt(15) =3

		A = sqrt(N) +1;
		//mpz_sqrt(A2, N2);
		//mpz_add_ui(A2,A2,1);
		//std::cout<<A<<std::endl<<A2<<std::endl<<std::endl;
		//mpz_pow_ui (temp2, A2, 2);
		//mpz_sub(temp2, temp2, N2);
		//mpz_sqrt(x2, temp2);

		x = sqrt(A*A - N);
		//mpz_sub(p2, A2, x2);
		//mpz_add(q2, A2, x2);
		p = A-x;
		q = A+x;
		res.push_back(p);
		res.push_back(q);
		return res;
}

//Returns the prob of a number being prime
unsigned int is_prime(mpz_t p)
{
	unsigned int res=0, prob=0;
	unsigned int is_prime  = mpz_probab_prime_p(p, prob);
	if (is_prime==2)
		res = 100;
	else if(is_prime==1)
		res = prob;
	else
		res =0;
	return res;
}
