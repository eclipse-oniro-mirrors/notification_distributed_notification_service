/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <memory>
#include <mutex>
#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <climits>
#include <cstdlib>

#include "openssl/evp.h"
#include "openssl/rand.h"

#include "aes_gcm_helper.h"
#include "ans_log_wrapper.h"
#include "ffrt.h"

namespace OHOS {
namespace Notification {
    static const uint32_t G_AES_GCM_KEY_LEN{32};
static const uint32_t G_AES_GCM_IV_LEN{12};
static const uint32_t G_AES_GCM_TAG_LEN{16};
static const std::string G_DIR_PATH{"/data/service/el1/public/database/notification_service/keyfile"};
static const std::string G_KEY_PATH{"/data/service/el1/public/database/notification_service"};
static const int STEP = 2;
static const int OFFSET = 4;
static const int HEX_OF_A = 10;
static const int WIDTH_PER_BYTE = 2;
static inline ffrt::mutex g_generateKeyMutex{};

std::string AesGcmHelper::Byte2Hex(const std::string &bytes)
{
    std::ostringstream oss;
    for (const unsigned char byte : bytes) {
        oss << std::hex << std::setw(WIDTH_PER_BYTE) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

unsigned char AesGcmHelper::HexChar2Byte(const char &hexCh)
{
    if (hexCh >= '0' && hexCh <= '9') {
        return hexCh - '0';
    } else if (hexCh >= 'A' && hexCh <= 'F') {
        return hexCh - 'A' + HEX_OF_A;
    } else if (hexCh >= 'a' && hexCh <= 'f') {
        return hexCh - 'a' + HEX_OF_A;
    } else {
        ANS_LOGE("Invalid hex char: %{public}c.", hexCh);
        return 0;
    }
}

std::string AesGcmHelper::Hex2Byte(const std::string &hex)
{
    if (hex.length() % STEP != 0) {
        ANS_LOGE("Length of hex is not even.");
        return 0;
    }
    std::string bytes;
    for (int i = 0; i < static_cast<int>(hex.length()); i += STEP) {
        unsigned char high = HexChar2Byte(hex[i]);
        unsigned char low = HexChar2Byte(hex[i + 1]);
        bytes.push_back(static_cast<char>((high << OFFSET) | low));
    }
    return bytes;
}

bool AesGcmHelper::GenerateKey(std::string &key)
{
    std::lock_guard<ffrt::mutex> lck(g_generateKeyMutex);
    const char *keyPathPtr = G_KEY_PATH.c_str();
    char *resolvedPath = (char *)malloc(PATH_MAX);
    if (resolvedPath != nullptr) {
        if (realpath(keyPathPtr, resolvedPath) == NULL) {
            free(resolvedPath);
            ANS_LOGE("Fail to resolve the key path");
            return false;
        }
        free(resolvedPath);
    }
    std::string keyDir = G_DIR_PATH;
    const char *fileNamePtr = keyDir.c_str();
    std::filesystem::path keyPath(keyDir);
    if (std::filesystem::exists(keyPath)) {
        std::ifstream keyFile(keyDir);
        if (keyFile.is_open()) {
            std::string keyHex;
            std::getline(keyFile, keyHex);
            key = Hex2Byte(keyHex);
            keyFile.close();
            return true;
        }
    }
    unsigned char aes_key[G_AES_GCM_KEY_LEN];
    if (!RAND_bytes(aes_key, G_AES_GCM_KEY_LEN)) {
        ANS_LOGE("Fail to randomly generate the key");
        return false;
    }
    key = std::string(reinterpret_cast<const char *>(aes_key), G_AES_GCM_KEY_LEN);
    std::string keyHex = Byte2Hex(key);
    if (!std::filesystem::exists(keyPath.parent_path())) {
        ANS_LOGE("Fail to save the key");
        return false;
    }
    std::ofstream keyFile(keyDir);
    if (keyFile.is_open()) {
        keyFile << keyHex;
        keyFile.close();
        ANS_LOGI("Generate new key.");
    } else {
        ANS_LOGE("Fail to save the key");
        return false;
    }
    return true;
}

ErrCode AesGcmHelper::Encrypt(const std::string &plainText, std::string &cipherText)
{
    if (plainText.empty()) {
        ANS_LOGE("Can't encrypt empty plain text.");
        return ERR_ANS_INVALID_PARAM;
    }
    std::string key{""};
    bool ret = GenerateKey(key);
    if (!ret) {
        ANS_LOGE("Fail to get key while encrypting.");
        return ERR_ANS_ENCRYPT_FAIL;
    }
    ret = EncryptAesGcm(plainText, cipherText, key);
    if (!ret) {
        ANS_LOGE("Fail to encrypt with AES-GCM.");
        return ERR_ANS_ENCRYPT_FAIL;
    }
    return ERR_OK;
}

ErrCode AesGcmHelper::Decrypt(std::string &plainText, const std::string &cipherText)
{
    if (cipherText.empty()) {
        ANS_LOGE("Can't decrypt empty cipher text.");
        return ERR_ANS_INVALID_PARAM;
    }
    std::string key{""};
    bool ret = GenerateKey(key);
    if (!ret) {
        ANS_LOGE("Fail to get key while decrypting");
        return ERR_ANS_DECRYPT_FAIL;
    }
    ret = DecryptAesGcm(plainText, cipherText, key);
    if (!ret) {
        ANS_LOGE("Fail to decrypt with AES-GCM.");
        return ERR_ANS_DECRYPT_FAIL;
    }
    return ERR_OK;
}

bool AesGcmHelper::EncryptAesGcm(const std::string &plainText, std::string &cipherText, std::string &key)
{
    const unsigned int bufferLen = plainText.size();
    std::vector<unsigned char> buffer(bufferLen);
    std::vector<unsigned char> iv(G_AES_GCM_IV_LEN);
    std::vector<unsigned char> tag(G_AES_GCM_TAG_LEN);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        ANS_LOGE("EncryptAesGcm ctx error");
        return false;
    }
    bool ret = true;
    do {
        if (!RAND_bytes(iv.data(), G_AES_GCM_IV_LEN)) {
            ANS_LOGE("EncryptAesGcm RAND_bytes error");
            ret = false;
            break;
        }
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
            reinterpret_cast<const unsigned char *>(key.data()), iv.data())) {
            ANS_LOGE("EncryptAesGcm EVP_EncryptInit_ex error");
            ret = false;
            break;
        }
        int len;
        if (!EVP_EncryptUpdate(ctx, buffer.data(), &len,
            reinterpret_cast<const unsigned char *>(plainText.data()), bufferLen)) {
            ANS_LOGE("EncryptAesGcm EVP_EncryptUpdate error");
            ret = false;
            break;
        }
        if (!EVP_EncryptFinal_ex(ctx, buffer.data() + len, &len)) {
            ANS_LOGE("EncryptAesGcm EVP_EncryptFinal_ex error");
            ret = false;
            break;
        }
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, G_AES_GCM_TAG_LEN, tag.data())) {
            ANS_LOGE("EncryptAesGcm EVP_CIPHER_CTX_ctrl error");
            ret = false;
            break;
        }
        cipherText = std::string(iv.begin(), iv.end());
        cipherText += std::string(buffer.begin(), buffer.end());
        cipherText += std::string(tag.begin(), tag.end());
        cipherText = Byte2Hex(cipherText);
    } while (0);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

bool AesGcmHelper::DecryptAesGcm(std::string &plainText, const std::string &cipherText, std::string &key)
{
    const unsigned int bufferLen = cipherText.size() - G_AES_GCM_IV_LEN - G_AES_GCM_TAG_LEN;
    std::vector<unsigned char> buffer(bufferLen);
    std::vector<unsigned char> iv(G_AES_GCM_IV_LEN);
    std::vector<unsigned char> cipherByte(bufferLen);
    std::vector<unsigned char> tag(G_AES_GCM_TAG_LEN);
    std::string cipherBytes = Hex2Byte(cipherText);
    iv.assign(cipherBytes.begin(), cipherBytes.begin() + G_AES_GCM_IV_LEN);
    cipherByte.assign(cipherBytes.begin() + G_AES_GCM_IV_LEN, cipherBytes.end() - G_AES_GCM_TAG_LEN);
    tag.assign(cipherBytes.end() - G_AES_GCM_TAG_LEN, cipherBytes.end());
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        ANS_LOGE("DecryptAesGcm ctx error");
        return false;
    }
    bool ret = true;
    do {
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
            reinterpret_cast<const unsigned char *>(key.data()), iv.data())) {
            ANS_LOGE("DecryptAesGcm EVP_DecryptInit_ex error");
            ret = false;
            break;
        }
        int len;
        if (!EVP_DecryptUpdate(ctx, buffer.data(), &len, cipherByte.data(), cipherByte.size())) {
            ANS_LOGE("DecryptAesGcm EVP_DecryptUpdate error");
            ret = false;
            break;
        }
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, G_AES_GCM_TAG_LEN, tag.data())) {
            ANS_LOGE("DecryptAesGcm EVP_CIPHER_CTX_ctrl error");
            ret = false;
            break;
        }
        if (EVP_DecryptFinal_ex(ctx, buffer.data() + len, &len) <= 0) {
            ANS_LOGE("DecryptAesGcm EVP_DecryptFinal_ex error");
            ret = false;
            break;
        }
        plainText = std::string(buffer.begin(), buffer.end());
    } while (0);
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

}  // namespace Notification
}  // namespace OHOS
