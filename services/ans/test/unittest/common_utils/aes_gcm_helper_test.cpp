/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/stat.h>

#include <gtest/gtest.h>

#define private public

#include "aes_gcm_helper.h"
#include "ans_inner_errors.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {
namespace {
constexpr const char *KEY_FILE_PATH = "/data/service/el1/public/database/notification_service/keyfile";
constexpr size_t AES_GCM_KEY_LEN = 32;
constexpr size_t MAX_CIPHER_TEXT_LEN = 16 * 1024 * 1024;
}

class AesGcmHelperUnitTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: EncryptAndDecryptWithCharAndNumber
 * @tc.desc: Test encrypt and decrypt with characters and numbers
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, EncryptAndDecryptWithCharAndNumber, Function | SmallTest | Level1)
{
    std::string test = "test12345";
    std::string temp;
    std::string result;

    AesGcmHelper::Encrypt(test, temp);
    AesGcmHelper::Decrypt(result, temp);

    ASSERT_EQ(result, test);
}

/**
 * @tc.name: EncryptAndDecryptWithSpecialSymbol
 * @tc.desc: Test encrypt and decrypt with special symbols
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, EncryptAndDecryptWithSpecialSymbol, Function | SmallTest | Level1)
{
    std::string test = "123:123:21?test.esult";
    std::string temp;
    std::string result;

    AesGcmHelper::Encrypt(test, temp);
    AesGcmHelper::Decrypt(result, temp);

    ASSERT_EQ(result, test);
}

/**
 * @tc.name: GenerateKeyWithValidKeyFile
 * @tc.desc: Test GenerateKey returns the same valid key when key file already exists
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, GenerateKeyWithValidKeyFile, Function | SmallTest | Level1)
{
    std::string key;
    ASSERT_TRUE(AesGcmHelper::GenerateKey(key));
    ASSERT_EQ(key.size(), AES_GCM_KEY_LEN);

    // second call should read the valid key file and return the same key
    std::string keyAgain;
    ASSERT_TRUE(AesGcmHelper::GenerateKey(keyAgain));
    EXPECT_EQ(keyAgain.size(), AES_GCM_KEY_LEN);
    EXPECT_EQ(key, keyAgain);
}

/**
 * @tc.name: GenerateKeyWithCorruptedKeyFile
 * @tc.desc: Test GenerateKey regenerates a new key when key file is corrupted
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, GenerateKeyWithCorruptedKeyFile, Function | SmallTest | Level1)
{
    struct stat fileStat;
    bool fileExisted = stat(KEY_FILE_PATH, &fileStat) == 0;
    std::string originalContent;
    if (fileExisted) {
        std::ifstream inFile(KEY_FILE_PATH, std::ios::binary);
        std::ostringstream ss;
        ss << inFile.rdbuf();
        originalContent = ss.str();
    }

    {
        std::ofstream outFile(KEY_FILE_PATH, std::ios::trunc | std::ios::binary);
        if (!outFile.is_open()) {
            GTEST_SKIP() << "key file is not writable in current environment";
        }
        outFile << "abcd"; // only 2 bytes after hex decoding, corrupted key
    }

    std::string cipherText;
    // corrupted key file should be regenerated, encrypt still succeeds
    EXPECT_EQ(AesGcmHelper::Encrypt("corruptedKeyTest", cipherText), ERR_OK);
    EXPECT_FALSE(cipherText.empty());
    std::string plainText;
    EXPECT_EQ(AesGcmHelper::Decrypt(plainText, cipherText), ERR_OK);
    EXPECT_EQ(plainText, "corruptedKeyTest");

    if (fileExisted) {
        std::ofstream outFile(KEY_FILE_PATH, std::ios::trunc | std::ios::binary);
        outFile << originalContent;
    } else {
        remove(KEY_FILE_PATH);
    }
}

/**
 * @tc.name: EncryptAesGcmWithInvalidKeyLength
 * @tc.desc: Test EncryptAesGcm returns false when key length is invalid
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, EncryptAesGcmWithInvalidKeyLength, Function | SmallTest | Level1)
{
    std::string key(AES_GCM_KEY_LEN / 2, 'k');
    std::string cipherText;
    EXPECT_FALSE(AesGcmHelper::EncryptAesGcm("plainText", cipherText, key));
    EXPECT_TRUE(cipherText.empty());
}

/**
 * @tc.name: DecryptAesGcmWithInvalidKeyLength
 * @tc.desc: Test DecryptAesGcm returns false when key length is invalid
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, DecryptAesGcmWithInvalidKeyLength, Function | SmallTest | Level1)
{
    std::string key(AES_GCM_KEY_LEN + 1, 'k');
    std::string plainText;
    EXPECT_FALSE(AesGcmHelper::DecryptAesGcm(plainText, "00112233445566778899aabbccddeeff", key));
    EXPECT_TRUE(plainText.empty());
}

/**
 * @tc.name: DecryptAesGcmWithTooLongCipherText
 * @tc.desc: Test DecryptAesGcm returns false when cipher text exceeds max length
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, DecryptAesGcmWithTooLongCipherText, Function | SmallTest | Level1)
{
    std::string key(AES_GCM_KEY_LEN, 'k');
    std::string plainText;
    std::string cipherText(MAX_CIPHER_TEXT_LEN + 1, 'a');
    EXPECT_FALSE(AesGcmHelper::DecryptAesGcm(plainText, cipherText, key));
    EXPECT_TRUE(plainText.empty());
}

/**
 * @tc.name: DecryptAesGcmWithShortCipherText
 * @tc.desc: Test DecryptAesGcm returns false when cipher bytes are shorter than IV plus TAG
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, DecryptAesGcmWithShortCipherText, Function | SmallTest | Level1)
{
    std::string key(AES_GCM_KEY_LEN, 'k');
    std::string plainText;
    // hex string of 28 bytes: IV(12) + TAG(16), no cipher payload
    EXPECT_FALSE(AesGcmHelper::DecryptAesGcm(plainText,
        "001122334455667788990011112233445566778899aabbccddeeff", key));
    EXPECT_TRUE(plainText.empty());
}

/**
 * @tc.name: EncryptAesGcmAndDecryptAesGcmRoundTrip
 * @tc.desc: Test EncryptAesGcm and DecryptAesGcm round trip with a valid key
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, EncryptAesGcmAndDecryptAesGcmRoundTrip, Function | SmallTest | Level1)
{
    std::string key(AES_GCM_KEY_LEN, 'k');
    std::string cipherText;
    ASSERT_TRUE(AesGcmHelper::EncryptAesGcm("roundTripTest", cipherText, key));
    EXPECT_FALSE(cipherText.empty());

    std::string plainText;
    ASSERT_TRUE(AesGcmHelper::DecryptAesGcm(plainText, cipherText, key));
    EXPECT_EQ(plainText, "roundTripTest");
}
}
}