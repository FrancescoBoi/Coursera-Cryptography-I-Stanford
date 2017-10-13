CC = g++
CFLAGS = -std=c++11 -I . -g3 -O2 -Wall -Wextra

Crypto.o: obj/CryptographyCoursera.o obj/Assignments.o obj/CryptoAlgos.o obj/utility.o obj
	$(CC) $(CFLAGS) obj/CryptographyCoursera.o obj/Assignments.o obj/CryptoAlgos.o obj/utility.o -o Crypto.o -lcryptopp -lgmp -lgmpxx

obj/%.o: %.cpp obj
	$(CC) $(CFLAGS) -c -o $@ $< 

obj:
	mkdir -p obj
