#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/osrng.h>

using namespace std;

// Функция для чтения содержимого файла
vector<uint8_t> readFile(const string& filepath) {
    ifstream file(filepath, ios::binary);
    if (!file) {
        cerr << "Ошибка открытия файла для чтения: " << filepath << endl;
        exit(1);
    }

    // Чтение данных из файла в вектор
    vector<uint8_t> data((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    return data;
}

// Функция для записи содержимого в файл
void writeFile(const string& filepath, const vector<uint8_t>& data) {
    ofstream file(filepath, ios::binary);
    if (!file) {
        cerr << "Ошибка открытия файла для записи: " << filepath << endl;
        exit(1);
    }

    // Запись данных из вектора в файл
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// Функция для генерации случайного IV (Initialization Vector)
CryptoPP::SecByteBlock generateRandomIV() {
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE); // IV размером с блок AES
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(iv, iv.size()); // Генерация случайного IV
    return iv;
}

// Функция для зашифрования данных
vector<uint8_t> encryptData(const vector<uint8_t>& data, const string& password) {
    vector<uint8_t> ciphertext;
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH); // Ключ размером с ключ AES

    // Генерация случайного IV
    CryptoPP::SecByteBlock iv = generateRandomIV();

    // Генерация ключа из пароля
    CryptoPP::PKCS12_PBKDF<CryptoPP::SHA256> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0,
        reinterpret_cast<const CryptoPP::byte*>(password.data()), password.size(),
        iv.data(), iv.size(), 1024, 0.0f);

    // Зашифрование данных в режиме CBC с использованием AES
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption(key, key.size(), iv);
    CryptoPP::StringSource ss(data.data(), data.size(), true,
        new CryptoPP::StreamTransformationFilter(encryption,
            new CryptoPP::VectorSink(ciphertext)
        )
    );

    // Добавление IV в начало шифротекста
    vector<uint8_t> result(iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    
    return result;
}

// Функция для расшифрования данных
vector<uint8_t> decryptData(const vector<uint8_t>& encryptedData, const string& password) {
    vector<uint8_t> plaintext;

    // Извлечение IV из начала шифротекста
    CryptoPP::SecByteBlock iv(encryptedData.data(), CryptoPP::AES::BLOCKSIZE);
    vector<uint8_t> ciphertext(encryptedData.begin() + CryptoPP::AES::BLOCKSIZE, encryptedData.end());
    
    CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);

    // Генерация ключа из пароля
    CryptoPP::PKCS12_PBKDF<CryptoPP::SHA256> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0,
        reinterpret_cast<const CryptoPP::byte*>(password.data()), password.size(),
        iv.data(), iv.size(), 1024, 0.0f);

    // Расшифрование данных в режиме CBC с использованием AES
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption(key, key.size(), iv);
    CryptoPP::StringSource ss(ciphertext.data(), ciphertext.size(), true,
        new CryptoPP::StreamTransformationFilter(decryption,
            new CryptoPP::VectorSink(plaintext)
        )
    );

    return plaintext;
}

// Функция для вывода справки
void printUsage(const char* programName) {
    cout << "Использование: " << programName << " -m [e | d] -k <ключ> -i <входной_файл> -о <выходной_файл>" << endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    string mode;
    string key;
    string inputFile;
    string outputFile;

    // Чтение аргументов командной строки
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "-m" && i + 1 < argc) {
            mode = argv[++i];
        } else if (arg == "-k" && i + 1 < argc) {
            key = argv[++i];
        } else if (arg == "-i" && i + 1 < argc) {
            inputFile = argv[++i];
        } else if (arg == "-o" && i + 1 < argc) {
            outputFile = argv[++i];
        }
    }

    // Проверка наличия необходимых аргументов
    if (key.empty() || inputFile.empty() || outputFile.empty() || (mode != "e" && mode != "d")) {
        printUsage(argv[0]);
        return 1;
    }

    // Чтение данных из входного файла
    vector<uint8_t> data = readFile(inputFile);
    vector<uint8_t> result;

    // Выполнение шифрования или расшифрования
    if (mode == "e") {
        result = encryptData(data, key);
    } else if (mode == "d") {
        result = decryptData(data, key);
    } 
    
    // Запись результата в выходной файл
    writeFile(outputFile, result);
    cout << "Операция завершена успешно." << endl;

    return 0;
}
