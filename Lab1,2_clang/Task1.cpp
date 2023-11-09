// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

// Header for working with files
#include "include/cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "include/cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "include/cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;


#include "include/cryptopp/filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::ArraySource;
using CryptoPP::ArraySink;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::Redirector;

#include "include/cryptopp/aes.h"
using CryptoPP::AES;

#include "include/cryptopp/base64.h"
#include "include/cryptopp/modes.h"
#include "include/cryptopp/ccm.h"
using CryptoPP::CBC_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CCM;

#include "include/cryptopp/xts.h"
using CryptoPP::XTS;
#include "include/cryptopp/gcm.h"
using CryptoPP::GCM;

#include <chrono>
#include <iostream>
using namespace std;
// using cout;
// using cerr;
// using endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

using namespace std;

AutoSeededRandomPool prng;
CryptoPP::byte key[AES::DEFAULT_KEYLENGTH];
CryptoPP::byte iv[AES::BLOCKSIZE];
string cipher, encoded, recovered, plain;
int optionMode;

void chooseKey() {
	int optionKey = 0;
	string fkey;
	string fiv;
	cout << "Select mode to choose the secret key and iv: \n";
	cout << "1. Random the secret key and iv \n";
	cout << "2. Enter the secret key and iv from screen \n";
	cout << "3. Enter the secret key and iv from file \n";
	cout << "Enter choice: ";
	cin >> optionKey;
	
	switch (optionKey)
	{
	case 1:
		if(optionMode == 1) {
			prng.GenerateBlock(key, sizeof(key));
		
		} else {
			prng.GenerateBlock(key, sizeof(key));
			prng.GenerateBlock(iv, sizeof(iv));
		}
		cout << "Generate secret key and iv successfull \n";
		break;
	
	case 2:
		cout << "Enter the input for secret key (length = 16): ";
		cin.ignore();
		getline(cin, fkey);
		StringSource(fkey, true, new HexEncoder(new ArraySink(key, sizeof(key))));
		if(optionMode != 1) {
			cout << "Enter the input for iv (length = 16): ";
			cin.ignore();
			getline(cin, fiv);
			StringSource(fiv, true, new HexEncoder(new ArraySink(iv, sizeof(fiv))));
		
		}
		break;

	case 3:
		cout << "Enter the key using file name: ";
		getline(cin, fkey);
		FileSource(fkey.data(), true, new ArraySink(key, sizeof(key)));
		cout << "Enter the iv using file name: ";
		getline(cin, fiv);
		FileSource(fiv.data(), true, new ArraySink(iv, sizeof(iv)));
		break;

	default:
		break;

	}
}

void chooseText(int optionCrypt) {
	int optionText = 0;
	string fplain, fcipher;

	cout << "1. Enter text from screen \n";
	cout << "2. Enter text from file (using file name) \n";
	cout << "Enter choice: ";
	cin >> optionText;

	switch (optionText)
	{
	case 1:
		if (optionCrypt == 1) {
			cout << "Enter the input for plaintext: ";
			cin.ignore();
			getline(cin, fplain);
			StringSource(fplain, true, new HexEncoder(new StringSink(plain)));
		} 
		else if (optionCrypt == 2) {
			cin.ignore();
			cout << "Enter the input for ciphertext: ";
			getline(cin, fcipher);
			StringSource(fcipher, true, new HexEncoder(new StringSink(cipher)));
		}
		break;
	
	case 2:
		if (optionCrypt == 1) {
			cout << "Enter the plaintext file using file name: ";
			cin.ignore();StringSource(fplain, true, new StringSink(plain));
			getline(cin, fplain);
			FileSource(fplain.data(), true,new HexEncoder(new StringSink(plain)));
		} 
		else if (optionCrypt == 2) {
			cout << "Enter the ciphertext file using file name: ";
			cin.ignore();
			getline(cin, fcipher);
			FileSource(fcipher.data(), true,new HexEncoder(new StringSink(cipher)));
		} 
	
		break;

	default:
		break;
	}
}

void printKey() {
	encoded.clear();
	StringSource(key, sizeof(key), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "key: " << encoded << endl;

	// Pretty print iv
	if(optionMode != 1) {
		encoded.clear();
		StringSource(iv, sizeof(iv), true,
			new HexEncoder(
				new StringSink(encoded)
			) // HexEncoder
		); // StringSource
	cout << "iv: " << encoded << endl;
	}
}

void encryptCBC() {
	 try
		{
		

		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter
		); // StringSource

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)plain.data(), plain.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher.data(), cipher.size());
#endif
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}



	
}

void decryptCBC() {
	
	try
	{
		

		CBC_Mode< AES >::Encryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}



}


void encryptECB() {
	
	try
	{
		ECB_Mode< AES >::Encryption e;
		e.SetKey(key, sizeof(key));
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	
#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif
	}

	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

void decryptECB() {
	try
	{
		ECB_Mode< AES >::Decryption d;
		d.SetKey(key, sizeof(key));
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

void encryptCFB() {
	

	try
	{
		CFB_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// CFB mode must not use padding. Specifying
		//  a scheme will result in an exception
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

void decryptCFB() {
	

	try
	{
		
		CFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

void encryptOFB() {
	try
	{

		OFB_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

void decryptOFB() {

	try
	{
		OFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

void encryptCTR() {

	try
	{
		

		CTR_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

void decryptCTR() {

	try
	{
		CTR_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

void encryptXTS() {
    try {
        CryptoPP::XTS_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, 32, iv);

#if 0
        std::cout << "key length: " << enc.DefaultKeyLength() << std::endl;
        std::cout << "key length (min): " << enc.MinKeyLength() << std::endl;
        std::cout << "key length (max): " << enc.MaxKeyLength() << std::endl;
        std::cout << "block size: " << enc.BlockSize() << std::endl;
#endif
        
        StringSource(plain, true, new StreamTransformationFilter(
                e, new StringSink(cipher), StreamTransformationFilter::NO_PADDING 
            )
        );
    }
    catch (const CryptoPP::Exception& exc) {
        std::cerr << exc.what() << std::endl;
        std::exit(1);
    }
}

void decryptXTS() {

    try {
        XTS_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, 32, iv);
        StringSource (cipher, true, new StreamTransformationFilter(
            d, new StringSink(recovered), StreamTransformationFilter::NO_PADDING
            )
        );
    }
    catch (const CryptoPP::Exception& exc) {
        cerr << exc.what() << std::endl;
        exit(1);
    }
}

const int TAG_SIZE = 8;

void encryptCCM() {
	

    try {
        CCM<AES, TAG_SIZE>::Encryption e;
        e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv, 12);
        e.SpecifyDataLengths(0, plain.size(), 0);
        StringSource(plain, true, new AuthenticatedEncryptionFilter(
                e, new StringSink(cipher) 
            )
        );
    }
    catch (const CryptoPP::Exception& exc) {
        cerr << exc.what() << std::endl;
        exit(1);
    }
}

void decryptCCM() {


    try {
        CCM<AES, TAG_SIZE>::Decryption d;
        d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv, 12);
        d.SpecifyDataLengths(0, cipher.size() - TAG_SIZE, 0);
        StringSource (cipher, true, new AuthenticatedDecryptionFilter(
            d, new StringSink(recovered)
            )
        );
    }
    catch (const CryptoPP::Exception& exc) {
        cerr << exc.what() << std::endl;
        exit(1);
    }
}

void encryptGCM() {


    try {
        GCM<AES>::Encryption e;
        e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv, AES::BLOCKSIZE);
        StringSource(plain, true, new AuthenticatedEncryptionFilter(
                e, new StringSink(cipher) 
            )
        );
    }
    catch (const CryptoPP::Exception& exc) {
        cerr << exc.what() << std::endl;
        exit(1);
    }
}

void decryptGCM() {
	
    try {
        GCM<AES>::Decryption d;
        d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv, AES::BLOCKSIZE);
        StringSource (cipher, true, new AuthenticatedDecryptionFilter(
            d, new StringSink(recovered)
            )
        );
    }
    catch (const CryptoPP::Exception& exc) {
        cerr << exc.what() << std::endl;
        exit(1);
    }
}

void chooseOutput(char optionCrypt) {
	int optionOutput = 0;
	cout << "Select the output type: \n";
	cout << "1. Display in screen \n";
	cout << "2. Write to file \n";
	cout << "Enter choice: ";
	cin >> optionOutput;
	switch (optionOutput)
	{
	case 1:
		if(optionCrypt == 1) {
			encoded.clear();
			StringSource(cipher, true,
				new HexEncoder(
					new StringSink(encoded)
				) // HexEncoder
			); // StringSource
			cout << "cipher text: " << encoded << endl;
		} else if(optionCrypt == 2) {
			encoded.clear();
			StringSource(recovered, true, //newHexEncoder
					new StringSink(encoded)
				 // HexEncoder
			); // StringSource
			cout << "plain text: " << encoded << endl;
		} else return;
		break;
	
	case 2: 
		if(optionCrypt == 2) {
			StringSource(cipher, true, new HexEncoder( new FileSink("cipherOut.txt", true)));
			
		} else if(optionCrypt == 'D') {
			StringSource(recovered, true, new FileSink("plainOut.txt", true));
		}		
	default:
		break;
	}
}

int main(int argc, char* argv[])
{
	#ifdef __linux__
    std::locale::global(std::locale("C.utf8"));
    #endif

	int optionCrypt;
	char isCheck, optionPrint;
	cout << "Select AES mode: \n";
	cout << "1. ECB \n";
	cout << "2. CBC \n";
	cout << "3. OFB \n";
	cout << "4. CFB \n";
	cout << "5. CTR \n";
	cout << "6. XTS \n";
	cout << "7. CCM \n";
	cout << "8. GCM \n";
	cout << "Enter choice: ";
	cin >> optionMode;
	

	int keySize = (optionMode == 6) ? 32 : AES::DEFAULT_KEYLENGTH;
    int ivSize = (optionMode == 7) ? 12 : AES::BLOCKSIZE;

    /* Initialize key */
    CryptoPP::byte newKey[keySize];

    /* Initialize initial vector (IV) */
    CryptoPP::byte newIV[ivSize];
	
	switch (optionMode)
	{
	case 1:
		chooseKey();
		
		cout << "1. Encrypt \t" << "2. Decrypt? \n" << "Enter choice (1/2): ";
		cin >> optionCrypt;
		switch (optionCrypt)
		{
		case 1:
			printKey();
			cout << "Select the mode to choose the plaintext: \n";
			chooseText(optionCrypt);
			cout << "Do you want to check the computation time? (Y/N): ";
			cin >> isCheck;
			if(tolower(isCheck) == 'y') {
				auto start = std::chrono::high_resolution_clock::now();
        
        		for (int i = 0; i < 1000; ++i) {
					encryptECB();
        		}

				auto end = chrono::high_resolution_clock::now();
				auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
				double averageTime = static_cast<double>(duration) / 1000.0;
				cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
			} else {
				encryptECB();
			}
			break;
		case 2: 
			cout << "Select the mode to choose the ciphertext: \n";
			chooseText(optionCrypt);
			cout << "Do you want to check the computation time? (Y/N): ";
			cin >> isCheck;
			if(tolower(isCheck) == 'y') {
				auto start = std::chrono::high_resolution_clock::now();
        
        		for (int i = 0; i < 1000; ++i) {
					decryptECB();
        		}

				auto end = chrono::high_resolution_clock::now();
				auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
				double averageTime = static_cast<double>(duration) / 1000.0;
				cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
			} else {
				decryptECB();
			}
			break;
		}
		chooseOutput(optionCrypt);
		break;

	case 2:
		chooseKey();
		
		cout << "1. Encrypt \t" << "2. Decrypt? \n" << "Enter choice (1/2): ";
		cin >> optionCrypt;
		switch (optionCrypt)
		{
		case 1:
			printKey();
			cout << "Select the mode to choose the plaintext: \n";
			chooseText(optionCrypt);
			cout << "Do you want to check the computation time? (Y/N): ";
			cin >> isCheck;
			if(tolower(isCheck) == 'y') {
				auto start = std::chrono::high_resolution_clock::now();
        
        		for (int i = 0; i < 1000; ++i) {
					encryptCBC();
        		}

				auto end = chrono::high_resolution_clock::now();
				auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
				double averageTime = static_cast<double>(duration) / 1000.0;
				cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
			} else {
				encryptCBC();
			}
			break;
		case 2: 
			cout << "Select the mode to choose the ciphertext: \n";
			chooseText(optionCrypt);
			cout << "Do you want to check the computation time? (Y/N): ";
			cin >> isCheck;
			if(tolower(isCheck) == 'y') {
				auto start = std::chrono::high_resolution_clock::now();
        
        		for (int i = 0; i < 1000; ++i) {
					decryptCBC();
        		}

				auto end = chrono::high_resolution_clock::now();
				auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
				double averageTime = static_cast<double>(duration) / 1000.0;
				cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
			} else {
				decryptCBC();
			}
			break;
		}
		chooseOutput(optionCrypt);
		break;

	case 3:
		chooseKey();
		
		cout << "1. Encrypt \t" << "2. Decrypt? \n" << "Enter choice (1/2): ";
		cin >> optionCrypt;
		
		switch (optionCrypt)
		{
		case 1:
			printKey();
			cout << "Select the mode to choose the plaintext: \n";
			chooseText(optionCrypt);
			cout << "Do you want to check the computation time? (Y/N): ";
			cin >> isCheck;
			if(tolower(isCheck) == 'y') {
				auto start = std::chrono::high_resolution_clock::now();
        
        		for (int i = 0; i < 1000; ++i) {
					encryptOFB();
        		}
				auto end = chrono::high_resolution_clock::now();
				auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
				double averageTime = static_cast<double>(duration) / 1000.0;
				cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
			} else {
				encryptOFB();
			}
			break;
		case 2: 
			cout << "Select the mode to choose the ciphertext: \n";
			chooseText(optionCrypt);
			cout << "Do you want to check the computation time? (Y/N): ";
			cin >> isCheck;
			if(tolower(isCheck) == 'y') {
				auto start = std::chrono::high_resolution_clock::now();
        
        		for (int i = 0; i < 1000; ++i) {
					decryptOFB();
        		}

				auto end = chrono::high_resolution_clock::now();
				auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
				double averageTime = static_cast<double>(duration) / 1000.0;
				cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
			} else {
				decryptOFB();
			}
			break;
		}
		chooseOutput(optionCrypt);
		break;
	
	case 4:
		chooseKey();
		
		cout << "1. Encrypt \t" << "2. Decrypt? \n" << "Enter choice (1/2): ";
		cin >> optionCrypt;
		switch (optionCrypt)
		{
		case 1:
			printKey();
			cout << "Select the mode to choose the plaintext: \n";
			chooseText(optionCrypt);
			cout << "Do you want to check the computation time? (Y/N): ";
			cin >> isCheck;
			if(tolower(isCheck) == 'y') {
				auto start = std::chrono::high_resolution_clock::now();
        
        		for (int i = 0; i < 1000; ++i) {
					encryptCFB();
        		}

				auto end = chrono::high_resolution_clock::now();
				auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
				double averageTime = static_cast<double>(duration) / 1000.0;
				cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
			} else {
				encryptCFB();
			}
			break;
		case 2: 
			cout << "Select the mode to choose the ciphertext: \n";
			chooseText(optionCrypt);
			cout << "Do you want to check the computation time? (Y/N): ";
			cin >> isCheck;
			if(tolower(isCheck) == 'y') {
				auto start = std::chrono::high_resolution_clock::now();
        
        		for (int i = 0; i < 1000; ++i) {
					decryptCFB();
        		}

				auto end = chrono::high_resolution_clock::now();
				auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
				double averageTime = static_cast<double>(duration) / 1000.0;
				cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
			} else {
				decryptCFB();
			}
			break;
		}
		chooseOutput(optionCrypt);

		break;

	case 5:
		chooseKey();
		
		cout << "1. Encrypt \t" << "2. Decrypt? \n" << "Enter choice (1/2): ";
		cin >> optionCrypt;
		switch (optionCrypt)
		{
		case 1:
			printKey();
			cout << "Select the mode to choose the plaintext: \n";
			chooseText(optionCrypt);
			cout << "Do you want to check the computation time? (Y/N): ";
			cin >> isCheck;
			if(tolower(isCheck) == 'y') {
				auto start = std::chrono::high_resolution_clock::now();
        
        		for (int i = 0; i < 1000; ++i) {
					encryptCTR();
        		}

				auto end = chrono::high_resolution_clock::now();
				auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
				double averageTime = static_cast<double>(duration) / 1000.0;
				cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
			} else {
				encryptCTR();
			}
			break;
		case 2: 
			cout << "Select the mode to choose the ciphertext: \n";
			chooseText(optionCrypt);
			cout << "Do you want to check the computation time? (Y/N): ";
			cin >> isCheck;
			if(tolower(isCheck) == 'y') {
				auto start = std::chrono::high_resolution_clock::now();
        
        		for (int i = 0; i < 1000; ++i) {
					decryptCTR();
        		}
				auto end = chrono::high_resolution_clock::now();
				auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
				double averageTime = static_cast<double>(duration) / 1000.0;
				cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
			} else {
				decryptCTR();
			}
			break;
		}
		chooseOutput(optionCrypt);
		break;

	case 6:
		chooseKey();
		StringSource(key, true, new HexEncoder(new ArraySink(newKey, sizeof(newKey))));
		StringSource(iv, true, new HexEncoder(new ArraySink(newIV, sizeof(newIV))));
		cout << "1. Encrypt \t" << "2. Decrypt? \n" << "Enter choice (1/2): ";
		cin >> optionCrypt;
		switch (optionCrypt)
		{
		case 1:
			
			cout << "Select the mode to choose the plaintext: \n";
			chooseText(optionCrypt);
			cout << "Do you want to check the computation time? (Y/N): ";
			cin >> isCheck;
			if(tolower(isCheck) == 'y') {
				auto start = std::chrono::high_resolution_clock::now();
        
        		for (int i = 0; i < 1000; ++i) {
					try {
						XTS_Mode<AES>::Encryption e;
						e.SetKeyWithIV(newKey, 32, newIV);

				#if 0
						std::cout << "key length: " << enc.DefaultKeyLength() << std::endl;
						std::cout << "key length (min): " << enc.MinKeyLength() << std::endl;
						std::cout << "key length (max): " << enc.MaxKeyLength() << std::endl;
						std::cout << "block size: " << enc.BlockSize() << std::endl;
				#endif
						
						StringSource(plain, true, new StreamTransformationFilter(
								e, new StringSink(cipher), StreamTransformationFilter::NO_PADDING 
							)
						);
					}
					catch (const Exception& exc) {
						cerr << exc.what() << endl;
						exit(1);
					}
        		}
				auto end = chrono::high_resolution_clock::now();
				auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
				double averageTime = static_cast<double>(duration) / 1000.0;
				cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
			} else {
				try {
						XTS_Mode<AES>::Encryption e;
						e.SetKeyWithIV(newKey, 32, newIV);

				#if 0
						std::cout << "key length: " << enc.DefaultKeyLength() << std::endl;
						std::cout << "key length (min): " << enc.MinKeyLength() << std::endl;
						std::cout << "key length (max): " << enc.MaxKeyLength() << std::endl;
						std::cout << "block size: " << enc.BlockSize() << std::endl;
				#endif
						
						StringSource(plain, true, new StreamTransformationFilter(
								e, new StringSink(cipher), StreamTransformationFilter::NO_PADDING 
							)
						);
					}
					catch (const Exception& exc) {
						cerr << exc.what() << endl;
						exit(1);
					}

			}
			break;
		case 2: 
			cout << "Select the mode to choose the ciphertext: \n";
			chooseText(optionCrypt);
			cout << "Do you want to check the computation time? (Y/N): ";
			cin >> isCheck;
			if(tolower(isCheck) == 'y') {
				auto start = std::chrono::high_resolution_clock::now();
        
        		for (int i = 0; i < 1000; ++i) {
					try {
        
						CryptoPP::XTS_Mode<AES>::Decryption d;
						d.SetKeyWithIV(newKey, 32, newIV);
						StringSource (cipher, true, new StreamTransformationFilter(
							d, new StringSink(recovered), StreamTransformationFilter::NO_PADDING
							)
        				);
					}
					catch (const CryptoPP::Exception& exc) {
						std::cerr << exc.what() << std::endl;
						std::exit(1);
					}

        		}
				auto end = chrono::high_resolution_clock::now();
				auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
				double averageTime = static_cast<double>(duration) / 1000.0;
				cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
			} else {
				try {
        
						XTS_Mode<AES>::Decryption d;
						d.SetKeyWithIV(newKey, 32, newIV);
						StringSource (cipher, true, new StreamTransformationFilter(
							d, new StringSink(recovered), StreamTransformationFilter::NO_PADDING
							)
        				);
					}
					catch (const Exception& exc) {
						cerr << exc.what() << endl;
						exit(1);
					}
			}
			break;
		}
		chooseOutput(optionCrypt);
		cout << "Do you want to print key and iv (if any) (Y/N): ";
		cin >> optionPrint;
		if(tolower(optionPrint) == 'y') {
			StringSource(newKey, sizeof(newKey), true, new FileSink("key.txt", sizeof(newKey)));
			StringSource(newIV, sizeof(newIV), true, new FileSink("iv.txt", sizeof(newIV)));
		}	
		break;

	case 7:
		chooseKey();
		StringSource(key, true, new HexEncoder(new ArraySink(newKey, sizeof(newKey))));
		StringSource(iv, true, new HexEncoder(new ArraySink(newIV, sizeof(newIV))));
		cout << "1. Encrypt \t" << "2. Decrypt? \n" << "Enter choice (1/2): ";
		cin >> optionCrypt;

		switch (optionCrypt)
		{
		case 1:
			printKey();
			
			cout << "Select the mode to choose the plaintext: \n";
			chooseText(optionCrypt);
			cout << "Do you want to check the computation time? (Y/N): ";
			cin >> isCheck;
			if(tolower(isCheck) == 'y') {
				auto start = std::chrono::high_resolution_clock::now();
        
        		for (int i = 0; i < 1000; ++i) {
					try {
						CCM<AES, TAG_SIZE>::Encryption e;
						e.SetKeyWithIV(newKey, AES::DEFAULT_KEYLENGTH, newIV, 12);
						e.SpecifyDataLengths(0, plain.size(), 0);
						StringSource(plain, true, new AuthenticatedEncryptionFilter(
								e, new StringSink(cipher) 
							)
						);
					}
					catch (const Exception& exc) {
						cerr << exc.what() << endl;
						exit(1);
					}
        		}

				auto end = chrono::high_resolution_clock::now();
				auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
				double averageTime = static_cast<double>(duration) / 1000.0;
				cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
			} else {
				try {
						CCM<AES, TAG_SIZE>::Encryption e;
						e.SetKeyWithIV(newKey, AES::DEFAULT_KEYLENGTH, newIV, 12);
						e.SpecifyDataLengths(0, plain.size(), 0);
						StringSource(plain, true, new AuthenticatedEncryptionFilter(
								e, new StringSink(cipher) 
							)
						);
					}
					catch (const Exception& exc) {
						cerr << exc.what() << endl;
						exit(1);
					}
			}
			break;
		case 2: 
			cout << "Select the mode to choose the ciphertext: \n";
			chooseText(optionCrypt);
			cout << "Do you want to check the computation time? (Y/N): ";
			cin >> isCheck;
			if(tolower(isCheck) == 'y') {
				auto start = std::chrono::high_resolution_clock::now();
        
        		for (int i = 0; i < 1000; ++i) {
					try {
						CCM<AES, TAG_SIZE>::Decryption d;
						d.SetKeyWithIV(newKey, AES::DEFAULT_KEYLENGTH, newIV, 12);
						d.SpecifyDataLengths(0, plain.size(), 0);
						StringSource(plain, true, new AuthenticatedEncryptionFilter(
								d, new StringSink(cipher) 
							)
						);
					}
					catch (const Exception& exc) {
						cerr << exc.what() << std::endl;
						exit(1);
					}
        		}

				auto end = chrono::high_resolution_clock::now();
				auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
				double averageTime = static_cast<double>(duration) / 1000.0;
				cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
			} else {
				try {
						CCM<AES, TAG_SIZE>::Decryption d;
						d.SetKeyWithIV(newKey, AES::DEFAULT_KEYLENGTH, newIV, 12);
						d.SpecifyDataLengths(0, plain.size(), 0);
						StringSource(plain, true, new AuthenticatedEncryptionFilter(
								d, new StringSink(cipher) 
							)
						);
					}
					catch (const Exception& exc) {
						cerr << exc.what() << endl;
						exit(1);
					}
			}
			break;
		}
		chooseOutput(optionCrypt);
		cout << "Do you want to print key and iv (if any) (Y/N): ";
		cin >> optionPrint;
		if(tolower(optionPrint) == 'y') {
			StringSource(newKey, sizeof(newKey), true, new FileSink("key.txt", sizeof(newKey)));
			StringSource(newIV, sizeof(newIV), true, new FileSink("iv.txt", sizeof(newIV)));
		}	
		break;

	case 8:
		chooseKey();
		StringSource(key, true, new HexEncoder(new ArraySink(newKey, sizeof(newKey))));
		StringSource(iv, true, new HexEncoder(new ArraySink(newIV, sizeof(newIV))));
		cout << "1. Encrypt \t" << "2. Decrypt? \n" << "Enter choice (1/2): ";
		cin >> optionCrypt;
		switch (optionCrypt)
		{
		case 1:
			printKey();
			cout << "Select the mode to choose the plaintext: \n";
			chooseText(optionCrypt);
			cout << "Do you want to check the computation time? (Y/N): ";
			cin >> isCheck;
			if(tolower(isCheck) == 'y') {
				auto start = std::chrono::high_resolution_clock::now();
        
        		for (int i = 0; i < 1000; ++i) {
					try {
						GCM<AES>::Encryption e;
						e.SetKeyWithIV(newKey, AES::DEFAULT_KEYLENGTH, newIV, AES::BLOCKSIZE);
						StringSource(plain, true, new AuthenticatedEncryptionFilter(
								e, new StringSink(cipher) 
							)
						);
					}
					catch (const Exception& exc) {
						cerr << exc.what() << endl;
						exit(1);
					}
        		}

				auto end = chrono::high_resolution_clock::now();
				auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
				double averageTime = static_cast<double>(duration) / 1000.0;
				cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
			} else {
				try {
						GCM<AES>::Encryption e;
						e.SetKeyWithIV(newKey, AES::DEFAULT_KEYLENGTH, newIV, AES::BLOCKSIZE);
						StringSource(plain, true, new AuthenticatedEncryptionFilter(
								e, new StringSink(cipher) 
							)
						);
					}
					catch (const Exception& exc) {
						cerr << exc.what() << endl;
						exit(1);
					}
			}
			break;
		case 2: 
			cout << "Select the mode to choose the ciphertext: \n";
			chooseText(optionCrypt);
			cout << "Do you want to check the computation time? (Y/N): ";
			cin >> isCheck;
			if(tolower(isCheck) == 'y') {
				auto start = std::chrono::high_resolution_clock::now();
        
        		for (int i = 0; i < 1000; ++i) {
					try {
						GCM<AES>::Decryption d;
						d.SetKeyWithIV(newKey, AES::DEFAULT_KEYLENGTH, newIV, AES::BLOCKSIZE);
						StringSource(plain, true, new AuthenticatedEncryptionFilter(
								d, new StringSink(cipher) 
							)
						);
					}
					catch (const Exception& exc) {
						cerr << exc.what() << endl;
						exit(1);
					}
        		}

				auto end = chrono::high_resolution_clock::now();
				auto duration = chrono::duration_cast<chrono::milliseconds>(end - start).count();
				double averageTime = static_cast<double>(duration) / 1000.0;
				cout << "Average time for encryption over 1000 rounds: " << averageTime << " ms" << std::endl;
			} else {
				try {
						GCM<AES>::Decryption d;
						d.SetKeyWithIV(newKey, AES::DEFAULT_KEYLENGTH, newIV, AES::BLOCKSIZE);
						StringSource(plain, true, new AuthenticatedEncryptionFilter(
								d, new StringSink(cipher) 
							)
						);
					}
					catch (const Exception& exc) {
						cerr << exc.what() << endl;
						exit(1);
					}
			}
			break;
		}
		chooseOutput(optionCrypt);
		
		cout << "Do you want to print key and iv (if any) (Y/N): ";
		cin >> optionPrint;
		if(tolower(optionPrint) == 'y') {
			StringSource(newKey, sizeof(newKey), true, new FileSink("key.txt", sizeof(newKey)));
			StringSource(newIV, sizeof(newIV), true, new FileSink("iv.txt", sizeof(newIV)));
		}
		break;

	default:
		break;
	}
	cout << "Do you want to print key and iv (if any) (Y/N): ";
	cin >> optionPrint;
	if(tolower(optionPrint) == 'y') {
		StringSource(key, sizeof(key), true, new FileSink("key.txt", sizeof(key)));
		if (optionMode == 1)
		{
			StringSource(iv, sizeof(iv), true, new FileSink("iv.txt", sizeof(iv)));
		}
	}
	return 0;
}