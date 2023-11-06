#include <string>
#include <vector>
#include "tables.h"

std::vector<int> rotWord(std::vector<int> word) {
  return {word[1], word[2], word[3], word[0]};
}

std::vector<int> subWord(std::vector<int> word) {
  std::vector<int> result;
  for (int byte : word) {
    result.push_back(S_BOX[byte]);
  }
  return result;
}

std::vector<std::vector<int>> keyExpansion(std::string key) {
  std::vector<std::vector<int>> word;

  for (int i = 0; i < key.length(); i += 4) {
    std::vector<int> subVec;
    for (int j = 0; j < 4; ++j) {
      subVec.push_back(int(key[i + j]));
    }
    word.push_back(subVec);
  }

  int wordLength = word.size();
  for (int i = wordLength; i < 44; ++i) {
    std::vector<int> temp = word[i - 1];
    if (i % wordLength == 0) {
      temp = subWord(rotWord(temp));
      for (int j = 0; j < 4; ++j) {
        temp[j] ^= RCON[(i - wordLength) / wordLength][j];
      }
    }
    std::vector<int> subVec;
    for (int j = 0; j < 4; ++j) {
      subVec.push_back(word[i - wordLength][j] ^ temp[j]);
    }
    word.push_back(subVec);
  }

  return word;
}
