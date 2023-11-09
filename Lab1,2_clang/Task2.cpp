#include "keyExpansion.h"
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>
using namespace std;

vector<vector<int>> padding(string plain) {
  int padding_length = 16 - (plain.length() % 16);
  plain.append(padding_length, char(padding_length));

  vector<vector<int>> state;
  for (int i = 0; i < plain.length(); i += 4) {
    vector<int> subVec;
    for (int j = 0; j < 4; ++j) {
      int temp = plain[i + j];
      if (temp < 0) {
        temp += 256;
      }
      subVec.push_back(int(temp));
    }
    state.push_back(subVec);
  }
  return state;
}

vector<vector<int>> addRoundKeys(vector<vector<int>> state,
                                           vector<vector<int>> word,
                                           int round) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      state[j][i] ^= word[round * 4 + i][j];
    }
  }
  return state;
}

vector<vector<int>> subBytes(vector<vector<int>> state) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      int row = state[i][j] / 16;
      int col = state[i][j] % 16;
      state[i][j] = S_BOX[16 * row + col];
    }
  }
  return state;
}

vector<vector<int>> shiftRows(vector<vector<int>> state) {
  for (int i = 0; i < 4; i++) {
    rotate(state[i].begin(), state[i].begin() + i, state[i].end());
  }
  return state;
}

int gmul(int a, int chCol) {
  int p = 0;
  for (int i = 0; i < 8; i++) {
    if (chCol & 1) {
      p ^= a;
    }
    int hiBitSet = a & 128;
    a <<= 1;
    if (hiBitSet) {
      a ^= 27;
    }
    chCol >>= 1;
  }
  return p % 256;
}

vector<vector<int>> mixColumns(vector<vector<int>> state) {
  for (int i = 0; i < 4; i++) {
    int s0 = state[0][i];
    int s1 = state[1][i];
    int s2 = state[2][i];
    int s3 = state[3][i];

    state[0][i] = gmul(s0, 0x02) ^ gmul(s1, 0x03) ^ s2 ^ s3;
    state[1][i] = s0 ^ gmul(s1, 0x02) ^ gmul(s2, 0x03) ^ s3;
    state[2][i] = s0 ^ s1 ^ gmul(s2, 0x02) ^ gmul(s3, 0x03);
    state[3][i] = gmul(s0, 0x03) ^ s1 ^ s2 ^ gmul(s3, 0x02);
  }
  return state;
}

vector<vector<int>> ECB_Encrypt(vector<vector<int>> state,
                                          vector<vector<int>> word,
                                          int totalRounds) {
  for (int i = 0; i < state.size(); i += 4) {
    vector<vector<int>> block(4, vector<int>(4));
    for (int j = 0; j < 4; j++) {
      for (int k = 0; k < 4; k++) {
        block[j][k] = state[i + j][k];
      }
    }

    /* First round */
    block = addRoundKeys(block, word, 0);

    /* Next rounds */
    for (int round = 1; round <= totalRounds - 1; round++) {
      block = subBytes(block);
      block = shiftRows(block);
      block = mixColumns(block);
      block = addRoundKeys(block, word, round);
    }

    /* Final round */
    block = subBytes(block);
    block = shiftRows(block);
    block = addRoundKeys(block, word, totalRounds);

    for (int j = 0; j < 4; ++j) {
      for (int k = 0; k < 4; ++k) {
        state[i + j][k] = block[j][k];
      }
    }
  }

  return state;
}

vector<vector<int>>
inverseSubBytes(vector<vector<int>> state) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      int row = state[i][j] / 16;
      int col = state[i][j] % 16;
      state[i][j] = INV_S_BOX[16 * row + col];
    }
  }
  return state;
}

vector<vector<int>>
inverseShiftRows(vector<vector<int>> state) {
  for (int i = 1; i < 4; i++) {
    rotate(state[i].begin(), state[i].begin() + 4 - i, state[i].end());
  }
  return state;
}

vector<vector<int>>
inverseMixColumns(vector<vector<int>> state) {
  for (int i = 0; i < 4; i++) {
    int s0 = state[0][i];
    int s1 = state[1][i];
    int s2 = state[2][i];
    int s3 = state[3][i];

    state[0][i] =
        gmul(s0, 0x0e) ^ gmul(s1, 0x0b) ^ gmul(s2, 0x0d) ^ gmul(s3, 0x09);
    state[1][i] =
        gmul(s0, 0x09) ^ gmul(s1, 0x0e) ^ gmul(s2, 0x0b) ^ gmul(s3, 0x0d);
    state[2][i] =
        gmul(s0, 0x0d) ^ gmul(s1, 0x09) ^ gmul(s2, 0x0e) ^ gmul(s3, 0x0b);
    state[3][i] =
        gmul(s0, 0x0b) ^ gmul(s1, 0x0d) ^ gmul(s2, 0x09) ^ gmul(s3, 0x0e);
  }
  return state;
}

vector<vector<int>> ECB_Decrypt(vector<vector<int>> state,
                                          vector<vector<int>> word,
                                          int totalRounds) {
  for (int i = 0; i < state.size(); i += 4) {
    vector<vector<int>> block(4, vector<int>(4));
    for (int j = 0; j < 4; j++) {
      for (int k = 0; k < 4; k++) {
        block[j][k] = state[i + j][k];
      }
    }

    /* First round */
    block = addRoundKeys(block, word, totalRounds);

    /* Next rounds */
    for (int round = totalRounds - 1; round > 0; round--) {
      block = inverseShiftRows(block);
      block = inverseSubBytes(block);
      block = addRoundKeys(block, word, round);
      block = inverseMixColumns(block);
    }

    /* Final round */
    block = inverseShiftRows(block);
    block = inverseSubBytes(block);
    block = addRoundKeys(block, word, 0);

    for (int j = 0; j < 4; ++j) {
      for (int k = 0; k < 4; ++k) {
        state[i + j][k] = block[j][k];
      }
    }
  }

  return state;
}

string byteToHex(vector<vector<int>> state) {
  stringstream hexString;

  for (const auto &row : state) {
    for (int value : row) {
      hexString << setw(2) << setfill('0') << hex << value;
    }
  }

  return hexString.str();
}

vector<vector<int>> hexToByte(string hexString) {
  vector<vector<int>> state;

  for (int i = 0; i < hexString.length(); i += 8) {
    vector<int> subVec;
    for (int j = 0; j < 8; j += 2) {
      string hexByte = hexString.substr(i + j, 2);
      subVec.push_back(stoi(hexByte, nullptr, 16));
    }
    state.push_back(subVec);
  }
  return state;
}

string recoverText(vector<vector<int>> state) {
  string recover;
  int padding_length = int(state.back().back());
  for (const auto &row : state) {
    for (int value : row) {
      recover += char(value);
    }
  }
  recover.resize(recover.length() - padding_length);

  return recover;
}

int main() {
/* Set locale to support UTF-8 */
  #ifdef __linux__
    locale::global(locale("C.utf8"));
  #endif

    /* Initialization */
    vector<vector<int>> word, state, encState;
    string plain, key;
    char option;

    /* Enter the key */
    cout << "Enter the key (exactly 16 bytes): ";
    getline(cin, key);

    /* Enter the plaintext */
    cout << "Enter the plaintext: ";
    getline(cin, plain);

    /* Encrypt */
    word = keyExpansion(key);
    state = padding(plain);

    state = ECB_Encrypt(state, word, 10);

    /* Output */
    string cipherEncoded = byteToHex(state);
    cout << "Key: " << key << endl;
    cout << "Plain: " << plain << endl;
    cout << "Cipher: " << cipherEncoded << endl;

    /* Decrypt */
    cout << "Would you like to recover this message? (y/N): ";
    option = getchar();

    if (tolower(option) == 'y') {
      encState = hexToByte(cipherEncoded);

      encState = ECB_Decrypt(encState, word, 10);

      string recover = recoverText(encState);
      cout << "Recovered text: " << recover << endl;
    } else {
      exit(0);
    }
    return 0;
}