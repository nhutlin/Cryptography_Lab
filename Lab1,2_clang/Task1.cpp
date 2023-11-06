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
int optionMode = 0;


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

void chooseText(char optionCrypt) {
	int optionText = 0;
	string fplain, fcipher;
	cout << "1. Enter text from screen \n";
	cout << "2. Enter text from file (using file name) \n";
	cout << "Enter choice: ";
	cin >> optionText;

	switch (optionText)
	{
	case 1:
		if (optionCrypt == 'E') {
			cout << "Enter the input for plaintext: ";
			cin.ignore();
			getline(cin, plain);
		} 
		else if (optionCrypt == 'D') {
			cin.ignore();
			cout << "Enter the input for ciphertext: ";
			getline(cin, cipher);
		}
		else return;
		break;
	
	case 2:
		if (optionCrypt == 'E') {
			cout << "Enter the plaintext file using file name: ";
			cin.ignore();
			getline(cin, fplain);
			FileSource(fplain.data(), true, new CryptoPP::StringSink(plain));
		} 
		else if (optionCrypt == 'D') {
			cout << "Enter the ciphertext file using file name: ";
			cin.ignore();
			getline(cin, fcipher);
			FileSource(fcipher.data(), true, new CryptoPP::StringSink(cipher));
		} 
		else return;
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
	// Pretty print key
	printKey();

try
	{
		cout << "plain text: " << plain << endl;

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

		// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;


}

void decryptCBC() {
	printKey();
	try
	{
		cout << "cipher text: " << cipher << endl;
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif

		//cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

void encryptECB() {
	printKey();
	try
	{
		cout << "plain text: " << plain << endl;

		ECB_Mode< AES >::Encryption e;
		e.SetKey(key, sizeof(key));

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
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

void decryptECB() {
	printKey();
	try
	{
		cout << "cipher text: " << cipher;
		ECB_Mode< AES >::Decryption d;
		d.SetKey(key, sizeof(key));

		// The StreamTransformationFilter removes
		//  padding as required.
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
	printKey();
	try
	{
		cout << "plain text: " << plain << endl;

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
	printKey();
	try
	{
		cout << "cipher text: " << cipher << endl;
		CFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

}

void encryptOFB() {
	printKey();
	try
	{
		cout << "plain text: " << plain << endl;

		OFB_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// OFB mode must not use padding. Specifying
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

void decryptOFB() {
	printKey();
	try
	{
		cout << "cipher text: " << cipher;
		OFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

void encryptCTR() {
	printKey();
	try
	{
		cout << "plain text: " << plain << endl;

		CTR_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
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
	printKey();

	try
	{
		cout << "cipher text: " << cipher << endl;
		CTR_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}

void encryptXTS() {
	printKey();
	cout << "plaint text: " << endl;
    try {
        XTS_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, 32, iv);

#if 0
        cout << "key length: " << enc.DefaultKeyLength() << endl;
        cout << "key length (min): " << enc.MinKeyLength() << endl;
        cout << "key length (max): " << enc.MaxKeyLength() << endl;
        cout << "block size: " << enc.BlockSize() << endl;
#endif
        
        StringSource(plain, true, new StreamTransformationFilter(
                e, new StringSink(cipher), StreamTransformationFilter::NO_PADDING 
            )
        );
    }
    catch (const CryptoPP::Exception& exc) {
        cerr << exc.what() << endl;
        exit(1);
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
		if(optionCrypt == 'E') {
			encoded.clear();
			StringSource(cipher, true,
				new HexEncoder(
					new StringSink(encoded)
				) // HexEncoder
			); // StringSource
			cout << "cipher text: " << encoded << endl;
		} else if(optionCrypt == 'D') {
			encoded.clear();
			StringSource(recovered, true,
				new HexEncoder(
					new StringSink(encoded)
				) // HexEncoder
			); // StringSource
			cout << "plain text: " << encoded << endl;
		} else return;
		break;
	
	case 2: 
		if(optionCrypt == 'E') {
			StringSource(cipher, true, new HexEncoder( new FileSink("cipherOut.txt", true)));
			
		} else if(optionCrypt == 'D') {
			StringSource(recovered, true,new HexEncoder(new FileSink("plainOut.txt", true)));
		}		
	default:
		break;
	}
}

int main(int argc, char* argv[])
{
	char optionCrypt = 'E';
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

	switch (optionMode)
	{
	case 1:
		chooseKey();
		cout << "Decrypt or Encrypt? (E or D): ";
		cin >> optionCrypt;
		switch (optionCrypt)
		{
		case 'E':
			cout << "Select the mode to choose the plaintext: \n";
			chooseText(optionCrypt);
			encryptECB();
			break;
		case 'D': 
			cout << "Select the mode to choose the ciphertext: \n";
			chooseText(optionCrypt);
			decryptECB();
			break;
		}
		chooseOutput(optionCrypt);
		break;

	case 2:
		chooseKey();
		cout << "Decrypt or Encrypt? (E or D): ";
		cin.ignore();
		cin >> optionCrypt;
		switch (optionCrypt)
		{
		case 'E':
			cout << "Select the mode to choose the plaintext: \n";
			chooseText(optionCrypt);
			encryptCBC();
			break;
		case 'D': 
			cout << "Select the mode to choose the ciphertext: \n";
			chooseText(optionCrypt);
			decryptCBC();
			break;
		}
		chooseOutput(optionCrypt);
		break;

	case 3:
		chooseKey();
		cout << "Decrypt or Encrypt? (E or D): ";
		cin.ignore();
		cin >> optionCrypt;
		switch (optionCrypt)
		{
		case 'E':
			cout << "Select the mode to choose the plaintext: \n";
			chooseText(optionCrypt);
			encryptOFB();
			break;
		case 'D': 
			cout << "Select the mode to choose the ciphertext: \n";
			chooseText(optionCrypt);
			decryptOFB();
			break;
		}
		chooseOutput(optionCrypt);
		break;
	
	case 4:
		chooseKey();
		cout << "Decrypt or Encrypt? (E or D): ";
		cin.ignore();
		cin >> optionCrypt;
		switch (optionCrypt)
		{
		case 'E':
			cout << "Select the mode to choose the plaintext: \n";
			chooseText(optionCrypt);
			encryptCFB();
			break;
		case 'D': 
			cout << "Select the mode to choose the ciphertext: \n";
			chooseText(optionCrypt);
			decryptCFB();
			break;
		}
		chooseOutput(optionCrypt);

		break;

	case 5:
		chooseKey();
		cout << "Decrypt or Encrypt? (E or D): ";
		cin.ignore();
		cin >> optionCrypt;
		switch (optionCrypt)
		{
		case 'E':
			cout << "Select the mode to choose the plaintext: \n";
			chooseText(optionCrypt);
			encryptCTR();
			break;
		case 'D': 
			cout << "Select the mode to choose the ciphertext: \n";
			chooseText(optionCrypt);
			decryptCTR();
			break;
		}
		chooseOutput(optionCrypt);
		break;

	case 6:
		chooseKey();
		cout << "Decrypt or Encrypt? (E or D): ";
		cin.ignore();
		cin >> optionCrypt;
		switch (optionCrypt)
		{
		case 'E':
			cout << "Select the mode to choose the plaintext: \n";
			chooseText(optionCrypt);
			encryptXTS();
			break;
		case 'D': 
			cout << "Select the mode to choose the ciphertext: \n";
			chooseText(optionCrypt);
			decryptXTS();
			break;
		}
		chooseOutput(optionCrypt);
		break;

	case 7:
		chooseKey();
		cout << "Decrypt or Encrypt? (E or D): ";
		cin.ignore();
		cin >> optionCrypt;
		switch (optionCrypt)
		{
		case 'E':
			cout << "Select the mode to choose the plaintext: \n";
			chooseText(optionCrypt);
			encryptCCM();
			break;
		case 'D': 
			cout << "Select the mode to choose the ciphertext: \n";
			chooseText(optionCrypt);
			decryptCCM();
			break;
		}
		chooseOutput(optionCrypt);

		break;

	case 8:
		chooseKey();
		cout << "Decrypt or Encrypt? (E or D): ";
		cin.ignore();
		cin >> optionCrypt;
		switch (optionCrypt)
		{
		case 'E':
			cout << "Select the mode to choose the plaintext: \n";
			chooseText(optionCrypt);
			encryptGCM();
			break;
		case 'D': 
			cout << "Select the mode to choose the ciphertext: \n";
			chooseText(optionCrypt);
			decryptGCM();
			break;
		}
		chooseOutput(optionCrypt);

		break;

	default:
		break;
	}

	return 0;
}

