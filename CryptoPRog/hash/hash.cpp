
#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>

using namespace std;

// Функция для чтения содержимого файла
vector<uint8_t> readFile(const string& filepath) {
    ifstream file(filepath, ios::binary);
    if (!file) {
        cerr << "Ошибка открытия файла: " << filepath << endl;
        exit(1);
    }

    vector<uint8_t> data((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    return data;
}

// Функция для вычисления SHA-256 хеша
string sha256(const vector<uint8_t>& data) {
    CryptoPP::SHA256 hash_func;
    string hash_hex;

    CryptoPP::StringSource(
        data.data(), data.size(), true,
        new CryptoPP::HashFilter(
            hash_func,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(hash_hex),
                true // Заглавные буквы
            )
        )
    );

    return hash_hex;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cout << "Использование: " << argv[0] << " <путь_к_файлу>" << endl;
        return 1;
    }

    string filepath = argv[1];
    vector<uint8_t> data = readFile(filepath);
    string hash = sha256(data);

    cout << "SHA-256 хеш файла " << filepath << ":\n" << hash << endl;
    return 0;
}
