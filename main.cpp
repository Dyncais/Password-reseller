#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <fstream>
#include <chrono>
#include <mutex>
#include "sha256.h"
#include <openssl/md5.h> //использование md5

std::mutex outputMutex;

void bruteForcePassword(int startRange, int endRange, const std::vector<std::string>& targetHashes) {
    std::string password = "aaaaa";

    for (int i = startRange; i < endRange; ++i) {
        int temp = i;
        for (int j = 4; j >= 0; --j) {
            password[j] = 'a' + (temp % 26);
            temp /= 26;
        }

        char hash[65] = {0};
        sha256_easy_hash_hex(password.c_str(), password.size(), hash);
        

        unsigned char md5_hash[MD5_DIGEST_LENGTH]; //здесь начало md5
        MD5(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), md5_hash);
       
        char md5_hex[33] = {0};
        for (int k = 0; k < MD5_DIGEST_LENGTH; ++k) {
            sprintf(&md5_hex[k * 2], "%02x", md5_hash[k]);
        }  // конец md5

        for (const auto& targetHash : targetHashes) {
            if ((static_cast<std::string>(hash) == targetHash) or (targetHash == md5_hex)) { // удалить поиск md5 @or (targetHash == md5_hex)@
                std::lock_guard<std::mutex> lock(outputMutex);
                auto endTime = std::chrono::high_resolution_clock::now();
                std::cout << "Пароль для хэша " << targetHash << " найден: " << password << '\n';
                break;
            }
        }
    }
}

int main() {
    int numThreads;
    std::cout << "Введите количество потоков: ";
    std::cin >> numThreads;
    if (numThreads < 1) numThreads = 1;

    std::ifstream file("hash.txt");
    if (!file) {
        std::cerr << "Не удалось открыть файл hash.txt.\n";
        return 1;
    }

    std::vector<std::string> targetHashes;
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) targetHashes.push_back(line);
    }
    file.close();

    if (targetHashes.empty()) {
        std::cerr << "Файл hash.txt пуст.\n";
        return 1;
    }

    int totalCombinations = 26 * 26 * 26 * 26 * 26;
    int rangePerThread = totalCombinations / numThreads;

    auto startTime = std::chrono::high_resolution_clock::now();

    std::vector<std::thread> threads;
    for (int i = 0; i < numThreads; ++i) {
        int startRange = i * rangePerThread;
        int endRange = (i == numThreads - 1) ? totalCombinations : startRange + rangePerThread;
        
        threads.emplace_back(bruteForcePassword, startRange, endRange, std::cref(targetHashes));
    }

    for (auto& thread : threads) {
        thread.join();
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = endTime - startTime;

    std::cout << "Полный поиск завершен за: " << duration.count() << " секунд.\n";
    return 0;
}
