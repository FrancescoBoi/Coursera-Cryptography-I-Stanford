/*
 * Assignment1.cpp
 *
 *  Created on: 01 ott 2017
 *      Author: carlo
 */

#include <Assignments.h>
#include<CryptoAlgos.h>
#include<fstream>
#include <boost/algorithm/hex.hpp>
#include<utility.h>
#include<iostream>
#include <crypto++/hex.h>
#include<gmp.h>

/*LOCAL FUNCTIONS USED IN ASSIGNMENT 6*/
void task1();
void task2();
void task3();
void task4();

/*Let us see what goes wrong when a stream cipher key is used more than once.
 * Below are eleven hex-encoded ciphertexts that are the result of encrypting eleven plaintexts
 * with a stream cipher, all with the same stream cipher key. Your goal is to decrypt the last ciphertext,
 *  and submit the secret message within it as solution.*/
int assignment1() {
    std::cout<<"----------------------ASSIGNMENT 1 -------------------------\n";
	std::ofstream out;
	out.open("/home/bigmac/Dropbox/coursera/Cryptography_Stanford/week1/res.txt");
	std::vector<std::string> myvect;
	//std::cout << "!!!Hello World!!!" << std::endl; // prints !!!Hello World!!!
	std::string ct1 ="315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804"
			 "e5ee9fa40b16349c146fb778cdf2d3aff021dfff5b403b510d0d0455468ae"
			 "b98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc5"
			 "7ee59418ce7dc6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987"
			 "815f65286764703de0f3d524400a19b159610b11ef3e";
	myvect.push_back(ct1);

	std::string ct2 = "234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf06"
			"4bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5069d9f7f543bedb9"
			"c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4"
			"480c82b2cb24cc5b028aa76eb7b4ab24171ab3cdadb8356f";
	myvect.push_back(ct2);

	std::string ct3 = "32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd9130"
			"4b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b70b9b8261112bacb6c8"
			"66a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f4"
			"1afa8d661cb";
	myvect.push_back(ct3);

	std::string ct4 = "32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064"
			"ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a81197847a5c68a1b787"
			"69a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520"
			"489e7da7d835402bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c"
			"767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa";
	myvect.push_back(ct4);

	std::string ct5 = "3f561ba9adb4b6ebec54424ba317b564418fac0dd35f8c08d31a"
			"1fe9e24fe56808c213f17c81d9607cee021dafe1e001b21ade877a5e68bea8"
			"8d61b93ac5ee0d562e8e9582f5ef375f0a4ae20ed86e935de81230b59b73fb"
			"4302cd95d770c65b40aaa065f2a5e33a5a0bb5dcaba43722130f042f8ec85b7"
			"c2070";
	myvect.push_back(ct5);

	std::string ct6 ="32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061"
			"bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee714979c7e1123a8bd9"
			"822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff1"
			"11284b4cc61d11902aebc66f2b2e436434eacc0aba938220b084800c2ca4e6"
			"93522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc229"
			"f77ace7aa88a2f19983122b11be87a59c355d25f8e4";
	myvect.push_back(ct6);

	std::string ct7 = "32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f"
			"1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148dd066592ded9f"
			"8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af5"
			"11039fa2d96f83414aaaf261bda2e97b170fb5cce2a53e675c154c0d9681596"
			"934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb02893283"
			"6fbdecfecee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661"
			"dd9a4ce";
	myvect.push_back(ct7);


	std::string ct8 ="315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4"
			"bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439fd0654327a3bfc"
			"860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba4"
			"10e9aa2ca24c5474da2f276baa3ac325918b2daada43d6712150441c2e04f6"
			"565517f317da9d3";
	myvect.push_back(ct8);

	std::string ct9 = "271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc910"
			"05e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987f4264edb6"
			"896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4"
			"564186a2c1778f1543efa270bda5e933421cbe88a4a52222190f471e9bd15f"
			"652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d020"
			"8573a7eef027";
	myvect.push_back(ct9);

	std::string ct10 = "466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf1"
			"10abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f32503beda"
			"c8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559b"
			"a520e89a2cb2a83";
	myvect.push_back(ct10);

	std::string target = "32510ba9babebbbefd001547a810e67149caee11d945cd7fc"
			"81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fde9e77472db"
			"ff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904";
	std::string myKey = attackOTP2(myvect, target);
	out<<(boost::algorithm::unhex(target)^myKey);
	out.close();
	std::cout<<"Quitting\n";
	return 0;
}

/*In this project you will implement two encryption/decryption systems, one using AES in CBC mode and another using AES in counter mode (CTR).
In both cases the 16-byte encryption IV is chosen at random and is prepended to the ciphertext.

For CBC encryption we use the PKCS5 padding scheme discussed in the lecture. While we ask that you implement both encryption and decryption, 
we will only test the decryption function. In the following questions you are given an AES key and a ciphertext (both are hex encoded ) 
and your goal is to recover the plaintext and enter it in the input boxes provided below.

For an implementation of AES you may use an existing crypto library such as PyCrypto (Python), Crypto++ (C++), or any other. 
While it is fine to use the built-in AES functions, we ask that as a learning experience you implement CBC and CTR modes yourself.*/
int assignment2()
{
    std::cout<<"----------------------ASSIGNMENT 2 -------------------------\n";
    std::vector<std::string> v_cbc_ct, v_ctr_ct;
	static const std::string s_key_cbc_hex = "140b41b22a29beb4061bda66b6747e14";
	static const std::string s_key_ctr_hex = "36f18357be4dbd77f050515c73fcf9f2";
	static const std::string s_cbc_ct1_hex = "4ca00ff4c898d61e1edbf1800618fb28"
											 "28a226d160dad07883d04e008a7897ee"
			"2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5d"
			"a05d9476be028ad7c1d81";
	static const std::string s_cbc_ct2_hex = "5b68629feb8606f9a6667670b75b38a5b4832d0f26"
			"e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21"
			"364b0c374df45503473c5242a253";

	static const std::string s_ctr_ct1_hex = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d"
			"1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabe"
			"dd9afa9329";
	static const std::string s_ctr_ct2_hex = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae4"
			"5faa8952aa0e311bde9d4e01726d3184c34451";
	static const std::string s_key_cbc = boost::algorithm::unhex(s_key_cbc_hex);
	static const std::string s_key_ctr = boost::algorithm::unhex(s_key_ctr_hex);
	static const std::string s_cbc_ct1 = boost::algorithm::unhex(s_cbc_ct1_hex);
	static const std::string s_cbc_ct2 = boost::algorithm::unhex(s_cbc_ct2_hex);
	static const std::string s_ctr_ct1 = boost::algorithm::unhex(s_ctr_ct1_hex);
	static const std::string s_ctr_ct2 = boost::algorithm::unhex(s_ctr_ct2_hex);
	v_cbc_ct.push_back(s_cbc_ct1);
	v_cbc_ct.push_back(s_cbc_ct2);
	v_ctr_ct.push_back(s_ctr_ct1);
	v_ctr_ct.push_back(s_ctr_ct2);
	unsigned int  ii, maxIter = v_cbc_ct.size() > v_ctr_ct.size() ? v_cbc_ct.size() : v_ctr_ct.size();

	for(ii=0; ii<maxIter; ii++)
	{
		if (ii<v_cbc_ct.size())
		{
			std::cout<<"\n---------CBC TEXT----------\n"
			<<cbc_AesDecrypt(v_cbc_ct.at(ii), s_key_cbc)<<std::endl;
			(void) cbc_test(v_cbc_ct.at(ii), cbc_AesDecrypt(v_cbc_ct.at(ii),
					s_key_cbc), s_key_cbc);
		}

		if (ii<v_ctr_ct.size())
			std::cout<<"\n\n---------CTR TEXT----------\n"
			<<ctr_AesDecrypt(v_ctr_ct.at(ii), s_key_ctr)<<"\n\n";
			(void) ctr_test(v_ctr_ct.at(ii), ctr_AesDecrypt(v_ctr_ct.at(ii),
					s_key_ctr), s_key_ctr);

	}
	return 0;
}


/*Suppose a web site hosts large video file F that anyone can download. Browsers who download the file need to make sure the file is authentic 
before displaying the content to the user.One approach is to have the web site hash the contents of F using a collision resistant hash and then 
distribute the resulting short hash value h=H(F) to users via some authenticated channel (later on we will use digital signatures for this). 
Browsers would download the entire file F, check that H(F) is equal to the authentic hash value h and if so, display the video to the user. 
Unfortunately, this means that the video will only begin playing after the *entire* file F has been downloaded.

Our goal in this project is to build a file authentication system that lets browsers authenticate and play video chunks as they are downloaded
without having to wait for the entire file. Instead of computing a hash of the entire file, the web site breaks the file into 1KB blocks (1024 bytes).
It computes the hash of the last block and appends the value to the second to last block. It then computes the hash of this augmented second to last
block and appends the resulting hash to the third block from the end. This process continues from the last block to the first as in the following diagram:



The final hash value h0 – a hash of the first block with its appended hash – is distributed to users via the authenticated channel as above.

Now, a browser downloads the file F one block at a time, where each block includes the appended hash value from the diagram above. When the first block (B0 ∥ h1) 
is received the browser checks that H(B0 ∥ h1) is equal to h0 and if so it begins playing the first video block. When the second block (B1 ∥ h2) is received the 
browser checks that H(B1 ∥ h2) is equal to h1 and if so it plays this second block. This process continues until the very last block. This way each block is
authenticated and played as it is received and there is no need to wait until the entire file is downloaded.

It is not difficult to argue that if the hash function H is collision resistant then an attacker cannot modify any of the video blocks without being detected by 
the browser. Indeed, since h0=H(B0 ∥ h1) an attacker cannot find a pair (B0′,h1′)≠(B0,h1) such that h0=H(B0′ ∥ h1′) since this would break collision resistance of H.
Therefore after the first hash check the browser is convinced that both B0 and h1 are authentic. Exactly the same argument proves that after the second hash check the
browser is convinced that both B1 and h2 are authentic, and so on for the remaining blocks.

In this project we will be using SHA256 as the hash function. For an implementation of SHA256 use an existing crypto library such as PyCrypto (Python), Crypto++ (C++), or any other.

When appending the hash value to each block, please append it as binary data, that is, as 32 unencoded bytes (which is 256 bits).
If the file size is not a multiple of 1KB then the very last block will be shorter than 1KB, but all other blocks will be exactly 1KB.

Your task is to write code to compute the hash h0 of a given file F and to verify blocks of F as they are received by the client.

In the box below please enter the (hex encoded) hash h0 for this video file:
https://crypto.stanford.edu/~dabo/onlineCrypto/6.1.intro.mp4_download

You can check your code by using it to hash a different file. In particular, the hex encoded h0 for the file at

https://crypto.stanford.edu/~dabo/onlineCrypto/6.2.birthday.mp4_download

is:
03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8
*/
int assignment3()
{
    std::cout<<"----------------------ASSIGNMENT 3 -------------------------\n";
    std::string fpath = "6.2.birthday.mp4_download";
	std::string fpath2 = "6.1.intro.mp4_download";
	(void) CalculateHash2(fpath, 1024);
	(void) CalculateHash2(fpath2, 1024);
    return 0;
}


/*Your goal this week is to write a program to compute discrete log modulo a prime p. Let g be some element in Zp∗ and suppose you are given h in Zp∗ such that h=gx where 1≤x≤240. Your goal is to find x. More precisely, the input to your program is p,g,h and the output is x.

The trivial algorithm for this problem is to try all 240 possible values of x until the correct one is found, that is until we find an x satisfying h=gx in Zp. This requires 240 multiplications. In this project you will implement an algorithm that runs in time roughly 240=220 using a meet in the middle attack.

Let B=220. Since x is less than B2

we can write the unknown x base B as x=x0B+x1

where x0,x1 are in the range [0,B−1]. Then

h=gx=gx0B+x1=(gB)x0⋅gx1   in Zp.

By moving the term gx1 to the other side we obtain

  h/gx1=(gB)x0   in Zp.

The variables in this equation are x0,x1 and everything else is known: you are given g,h and B=220. Since the variables x0 and x1 are now on different sides of the equation we can find a solution using meet in the middle (Lecture 3.3 at 14:25):

    First build a hash table of all possible values of the left hand side h/gx1 for x1=0,1,…,220.
    Then for each value x0=0,1,2,…,220 check if the right hand side (gB)x0 is in this hash table. If so, then you have found a solution (x0,x1) from which you can compute the required x as x=x0B+x1. 

The overall work is about 220 multiplications to build the table and another 220 lookups in this table.

Now that we have an algorithm, here is the problem to solve:

p=134078079299425970995740249982058461274793658205923933 \77723561443721764030073546976801874298166903427690031 \858186486050853753882811946569946433649006084171g=11717829880366207009516117596335367088558084999998952205 \59997945906392949973658374667057217647146031292859482967 \5428279466566527115212748467589894601965568h=323947510405045044356526437872806578864909752095244 \952783479245297198197614329255807385693795855318053 \2878928001494706097394108577585732452307673444020333

Each of these three numbers is about 153 digits. Find x such that h=gx in Zp.

To solve this assignment it is best to use an environment that supports multi-precision and modular arithmetic. In Python you could use the gmpy2 or numbthy modules. Both can be used for modular inversion and exponentiation. In C you can use GMP. In Java use a BigInteger class which can perform mod, modPow and modInverse operations.*/
int assignment5()
{
    std::cout<<"----------------------ASSIGNMENT 5 -------------------------\n";
    mpz_t p;
	mpz_init(p);
	mpz_set_str(p,
			"134078079299425970995740249982058461274793658205923933"
			"77723561443721764030073546976801874298166903427690031"
			"858186486050853753882811946569946433649006084171",10);

	//mpz_set_ui(p,497);
	gmp_printf("%Zd\n", p);
	mpz_t g;
	mpz_init(g);
	//mpz_set_ui(g,4);
	mpz_set_str(g,
			"11717829880366207009516117596335367088558084999998952205"
			"59997945906392949973658374667057217647146031292859482967"
			"5428279466566527115212748467589894601965568",10);


	mpz_t h;
	mpz_init(h);
	mpz_set_str(h,
			"323947510405045044356526437872806578864909752095244"
			"952783479245297198197614329255807385693795855318053"
			"2878928001494706097394108577585732452307673444020333",10);

	mpz_t res;
	mpz_init_set_ui(res, 0);
	std::string iv = "20814804c1767293b99f1d9cab3bc3e7";
	iv = boost::algorithm::unhex(iv);
	std::cout<<boost::algorithm::hex(iv)<<std::endl;
	std::cout<<toLower(boost::algorithm::hex(iv ^ "Pay Bob 100$" ^ "Pay Bob 500$"))<<std::endl;

	std::cout<<toLower(boost::algorithm::hex(iv^std::string("Pay Bob 100$") ^ std::string("Pay Bob 500$")))<<std::endl;
	DHLog(p, g, h, 40);
	//week1q7();

	return 0;
}

/*Your goal in this project is to break RSA when the public modulus N is generated incorrectly. This should serve as yet another reminder not to implement crypto primitives yourself.

Normally, the primes that comprise an RSA modulus are generated independently of one another. But suppose a developer decides to generate the first prime p by choosing a random number R and scanning for a prime close by. The second prime q is generated by scanning for some other random prime also close to R.

We show that the resulting RSA modulus N=pq can be easily factored.

Suppose you are given a composite N and are told that N is a product of two relatively close primes p and q, namely p and q satisfy

|p−q|<2*N^(1/4) (*)

Your goal is to factor N.

Let A be the arithmetic average of the two primes, that is A=(p+q)/2. Since p and q are odd, we know that p+q is even and therefore A is an integer.

To factor N you first observe that under condition (*) the quantity N is very close to A. In particular, we show below that:

A−sqrt(N)<1

But since A is an integer, rounding sqrt(N) up to the closest integer reveals the value of A. In code, A=ceil(sqrt(N)) where "ceil" is the ceiling function.

Visually, the numbers p,q,sqrt(N) and A are ordered as follows:
----p------------------------------sqrt(N)-----A=(p+q)/2----

Since A is the exact mid-point between p and q there is an integer x such that p=A−x and q=A+x.

But then N=pq=(A−x)(A+x)=A^2−x^2 and therefore x=sqrt(A^2−N).

Now, given x and A you can find the factors p and q of N since p=A−x and q=A+x. You have now factored N  !

Further reading: the method described above is a greatly simplified version of a much more general result on factoring when the high order bits of the prime factor are known.

In the following challenges, you will factor the given moduli using the method outlined above. To solve this assignment it is best to use an environment that supports multi-precision arithmetic and square roots. In Python you could use the gmpy2 module. In C you can use GMP.*/
int assignment6()
{
    task1();
    sleep(3);
    task2();
    sleep(3);
    task3();
    sleep(3);
    task4();
    return 0;
    
}

/*The following modulus N is a products of two primes p and q where |p−q|<2N*1/4. Find the smaller of the two factors and enter it as a decimal integer in the box below.

For completeness, let us see why A−sqrt(N)<1. This follows from the following simple calculation.

First observe that A^2−N=((p+q2)^2)/2−N=(p^2+2N+q^2)/4−N=(p^2−2N+q^2)/4=((p−q)^2)/4.

Now, since for all x,y:  (x−y)(x+y)=x^2−y^2 we obtain A−sqrt(N)=(A−sqrt(N))*(A+sqrt(N))/(A+sqrt(N))=A^2−NA+N=(p−q)2/4A+N.

Since N≤A it follows that A−sqrt(N)≤((p−q)^2/4)(2*sqrt(N))=(p−q)^2/(8*sqrt(N)).

By assumption (*) we know that (p−q)^2<4sqrt(N) and therefore A−sqrt(N)≤4sqrt(N)/(8sqrt(N)=1/2 as required.*/
void task1()
{
	mpz_class N;
	std::vector<mpz_class> res;

	N = "17976931348623159077293051907890247336179769789423065727343008115"
					"77326758055056206869853794492129829595855013875371640157101398586"
					"47833778606925583497541085196591615128057575940752635007475935288"
					"71082364994994077189561705436114947486504671101510156394068052754"
					"0071584560878577663743040086340742855278549092581";
	res = defactor_p_q_close(N);
	if( (is_prime(res.at(0).get_mpz_t()) + is_prime(res.at(1).get_mpz_t())) == 200)
		std::cout<<"p, q are primes: \n";
	else
		std::cout<<"p, q are primes: \n";
	std::cout << "The two primes are: \n" << res.at(0)<<"\n"<<res.at(1) << "\n";

}

/*Factoring challenge #2:

The following modulus N is a products of two primes p and q where |p−q|<211N1/4. Find the smaller of the two factors and enter it as a decimal integer.

Hint: in this case A−N<220 so try scanning for A from N upwards, until you succeed in factoring N. */
void task2()
/*
 *
 The following modulus N is a products of two primes p and q where |p−q|<2^11 * N^(1/4).
 Find the smaller of the two factors and enter it as a decimal integer.

Hint: in this case A−sqrt(N)<2^20 so try scanning for A from sqrt(N) upwards, until you succeed in factoring N.
*/
{
	std::cout<<"\n------------------------------------------------------------TASK 2------------------------------------------------------------\n";
	mpz_class N;
	N = "6484558428080716696628242653467722787263437207069762630604390703787"
			"9730861808111646271401527606141756919558732184025452065542490671989"
			"2428844841839353281972988531310511738648965962582821502504990264452"
			"1008852816733037111422964210278402893076574586452336833570778346897"
			"15838646088239640236866252211790085787877";

	mpz_class A = sqrt(N) + 1;
	mpz_class x;
	x ="0";
	mpz_class p, q, N_hat;
	p="0";
	q="0";
	N_hat = "0";
	unsigned int c=0;
	unsigned const int max_iter = pow(2,20);

	while(c < max_iter)
	{
		x = sqrt(A*A - N);
		p = A - x;
		q = A + x;
		N_hat = p*q;
		if (!mpz_cmp( N.get_mpz_t(), N_hat.get_mpz_t() ) ) //if the 2 are equals, cmp returns 0
		{
			std::cout<<"The two primes are \n"<<p<<std::endl<<q<<std::endl;
			break;
		}
		A++;
		c++;

	}
	std::cout<<"Check: \n"<<N<<std::endl;
	mpz_class N_h;
	N_h = p * q;
	std::cout<<N_h<<std::endl;

	if( (is_prime(p.get_mpz_t()) + is_prime	(q.get_mpz_t())) == 200)
		std::cout<<"p, q are primes: \n";
	else
		std::cout<<"p, q are primes: \n";
	std::cout<<"Task 2 completed\n";
}



void task3()
{
	std::cout<<"\n------------------------------------------------------------TASK 3------------------------------------------------------------\n";

	mpz_class N, N_times24, p, q;
	std::vector<mpz_class> res;
	N = "72006226374735042527956443552558373833808445147399984182665305798191"
			"63556901883377904234086641876639384851752649940178970835240791356868"
			"77441155132015188279331812309091996246361896836573643119174094961348"
			"52463970788523879939683923036467667022162701835329944324119217381272"
			"9276147530748597302192751375739387929";
	N_times24 = N*24;

	res = defactor_p_q_close(N_times24);
	/*mpz_class A, x, p, q;
	A = 2*(sqrt(6*N))+1;
	x = sqrt(A*A - 24*N);
	p = A - x;
	q = A + x;
	mpz_class t;

	t = 6*N;
	//std::cout<<"Check: \n";//<<t<<std::endl;
	t = p *q;
	std::cout<<q<<std::endl<<std::endl;*/
	q = res.at(1)/4;
	p = res.at(0)/6;



	std::cout<<"Check: \n"<<N<<std::endl;
	mpz_class N_h;
	N_h = p * q;
	std::cout<<N_h<<std::endl;

	if( (is_prime(res.at(0).get_mpz_t()) + is_prime(res.at(1).get_mpz_t())) == 200)
		std::cout<<"p, q are primes: \n";
	else
		std::cout<<"p, q are primes: \n";
	std::cout << "The two primes are: \n" << p<<"\n"<<q << "\n";

}

void task4()
{
	std::cout<<"\n------------------------------------------------------------TASK 4------------------------------------------------------------\n";
	mpz_class e,N, phi_N, check, x, y, ct;
	std::vector<mpz_class> p_q;
	e = "65537";
	mpz_class N2;
	N = "17976931348623159077293051907890247336179769789423065727343008115"
					"77326758055056206869853794492129829595855013875371640157101398586"
					"47833778606925583497541085196591615128057575940752635007475935288"
					"71082364994994077189561705436114947486504671101510156394068052754"
					"0071584560878577663743040086340742855278549092581";
	mpz_set_str(N2.get_mpz_t(), "17976931348623159077293051907890247336179769789423065727343008115"
			"77326758055056206869853794492129829595855013875371640157101398586"
			"47833778606925583497541085196591615128057575940752635007475935288"
			"71082364994994077189561705436114947486504671101510156394068052754"
			"0071584560878577663743040086340742855278549092581", 16);
	ct = "22096451867410381776306561134883418017410069787892831071731839143"
			"67613560012053800428232965047350942434394621975151225646583996794288946076"
			"45420405815647489880137348641204523252293201764879166664029975091887299716"
			"90526083222067771600019329260870009579993724077458967773697817571267229951"
			"148662959627934791540";
	//std::cout<<N.ge<<std::endl;
	p_q = defactor_p_q_close(N);
	phi_N = (p_q.at(0) - 1)* (p_q.at(1) - 1);
	mpz_class d;
	d = "0";
	x = "0";
	mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi_N.get_mpz_t());
	check = d*e;
	mpz_mod(check.get_mpz_t(), check.get_mpz_t(), phi_N.get_mpz_t());

	std::cout<<"Check: "<< check<<std::endl;
	mpz_powm(x.get_mpz_t(), ct.get_mpz_t(), d.get_mpz_t(), N.get_mpz_t());
	std::string res = toFormatFromDecimal(x);
	std::cout<<res<<std::endl;
	res = res.substr(res.find("00")+2, res.length()-res.find("00")-2);
	std::cout<<boost::algorithm::unhex(res)<<std::endl;

	//std::cout<<x<<std::endl;
	//std::cout<<std::endl<<t<<std::endl;
}