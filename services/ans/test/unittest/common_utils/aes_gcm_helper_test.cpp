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

#include <gtest/gtest.h>

#define private public

#include "aes_gcm_helper.h"

using namespace testing::ext;

namespace OHOS {
namespace Notification {

class AesGcmHelperUnitTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: Hex2Byte_00001
 * @tc.desc: Test Hex2Byte with valid even length lowercase string
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, Hex2Byte_00001, Function | SmallTest | Level1)
{
    std::string hex = "abcd";
    std::string result = AesGcmHelper::Hex2Byte(hex);
    EXPECT_EQ(result.length(), 2);
    EXPECT_EQ(result[0], static_cast<char>(0xAB));
    EXPECT_EQ(result[1], static_cast<char>(0xCD));
}

/**
 * @tc.name: Hex2Byte_00002
 * @tc.desc: Test Hex2Byte with valid even length mixed case string
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, Hex2Byte_00002, Function | SmallTest | Level1)
{
    std::string hex = "AbCd";
    std::string result = AesGcmHelper::Hex2Byte(hex);
    EXPECT_EQ(result.length(), 2);
    EXPECT_EQ(result[0], static_cast<char>(0xAB));
    EXPECT_EQ(result[1], static_cast<char>(0xCD));
}

/**
 * @tc.name: Hex2Byte_00003
 * @tc.desc: Test Hex2Byte with valid even length digit string
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, Hex2Byte_00003, Function | SmallTest | Level1)
{
    std::string hex = "01020304";
    std::string result = AesGcmHelper::Hex2Byte(hex);
    EXPECT_EQ(result.length(), 4);
    EXPECT_EQ(result[0], static_cast<char>(0x01));
    EXPECT_EQ(result[1], static_cast<char>(0x02));
    EXPECT_EQ(result[2], static_cast<char>(0x03));
    EXPECT_EQ(result[3], static_cast<char>(0x04));
}

/**
 * @tc.name: Hex2Byte_00004
 * @tc.desc: Test Hex2Byte with valid even length uppercase string
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, Hex2Byte_00004, Function | SmallTest | Level1)
{
    std::string hex = "ABCD";
    std::string result = AesGcmHelper::Hex2Byte(hex);
    EXPECT_EQ(result.length(), 2);
    EXPECT_EQ(result[0], static_cast<char>(0xAB));
    EXPECT_EQ(result[1], static_cast<char>(0xCD));
}

/**
 * @tc.name: Hex2Byte_00005
 * @tc.desc: Test Hex2Byte with invalid character in string
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, Hex2Byte_00005, Function | SmallTest | Level1)
{
    std::string hex = "g0";
    std::string result = AesGcmHelper::Hex2Byte(hex);
    EXPECT_EQ(result.length(), 1);
    EXPECT_EQ(result[0], static_cast<char>(0x00));
}

/**
 * @tc.name: Encrypt_00001
 * @tc.desc: Test Encrypt with long text
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, Encrypt_00001, Function | SmallTest | Level1)
{
    std::string plainText = "This is a long text for testing AES-GCM encryption functionality";
    std::string cipherText;
    ErrCode result = AesGcmHelper::Encrypt(plainText, cipherText);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(!cipherText.empty());
}

/**
 * @tc.name: Encrypt_00002
 * @tc.desc: Test Encrypt with valid plain text
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, Encrypt_00002, Function | SmallTest | Level1)
{
    std::string plainText = "test12345";
    std::string cipherText;
    ErrCode result = AesGcmHelper::Encrypt(plainText, cipherText);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(!cipherText.empty());
}

/**
 * @tc.name: Encrypt_00003
 * @tc.desc: Test Encrypt with special characters
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, Encrypt_00003, Function | SmallTest | Level1)
{
    std::string plainText = "123:123:21?test.esult";
    std::string cipherText;
    ErrCode result = AesGcmHelper::Encrypt(plainText, cipherText);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(!cipherText.empty());
}

/**
 * @tc.name: Encrypt_00004
 * @tc.desc: Test Encrypt with single character
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, Encrypt_00004, Function | SmallTest | Level1)
{
    std::string plainText = "a";
    std::string cipherText;
    ErrCode result = AesGcmHelper::Encrypt(plainText, cipherText);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(!cipherText.empty());
}

/**
 * @tc.name: Decrypt_00001
 * @tc.desc: Test Decrypt with empty cipher text
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, Decrypt_00001, Function | SmallTest | Level1)
{
    std::string plainText;
    std::string cipherText = "";
    ErrCode result = AesGcmHelper::Decrypt(plainText, cipherText);
    EXPECT_EQ(result, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: Decrypt_00002
 * @tc.desc: Test Decrypt with valid cipher text
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, Decrypt_00002, Function | SmallTest | Level1)
{
    std::string plainText = "test12345";
    std::string cipherText;
    ErrCode encryptResult = AesGcmHelper::Encrypt(plainText, cipherText);
    EXPECT_EQ(encryptResult, ERR_OK);
    
    std::string decryptedText;
    ErrCode decryptResult = AesGcmHelper::Decrypt(decryptedText, cipherText);
    EXPECT_EQ(decryptResult, ERR_OK);
    EXPECT_EQ(decryptedText, plainText);
}

/**
 * @tc.name: Decrypt_00003
 * @tc.desc: Test Decrypt with special characters cipher text
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, Decrypt_00003, Function | SmallTest | Level1)
{
    std::string plainText = "123:123:21?test.esult";
    std::string cipherText;
    ErrCode encryptResult = AesGcmHelper::Encrypt(plainText, cipherText);
    EXPECT_EQ(encryptResult, ERR_OK);
    
    std::string decryptedText;
    ErrCode decryptResult = AesGcmHelper::Decrypt(decryptedText, cipherText);
    EXPECT_EQ(decryptResult, ERR_OK);
    EXPECT_EQ(decryptedText, plainText);
}

/**
 * @tc.name: Decrypt_00004
 * @tc.desc: Test Decrypt with corrupted cipher text
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, Decrypt_00004, Function | SmallTest | Level1)
{
    std::string plainText = "test";
    std::string cipherText;
    ErrCode encryptResult = AesGcmHelper::Encrypt(plainText, cipherText);
    EXPECT_EQ(encryptResult, ERR_OK);
    
    if (cipherText.length() > 4) {
        cipherText[cipherText.length() - 1] = '0';
    }
    
    std::string decryptedText;
    ErrCode decryptResult = AesGcmHelper::Decrypt(decryptedText, cipherText);
    EXPECT_NE(decryptResult, ERR_OK);
}

/**
 * @tc.name: EncryptAndDecrypt_00001
 * @tc.desc: Test encrypt and decrypt roundtrip with Chinese characters
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, EncryptAndDecrypt_00001, Function | SmallTest | Level1)
{
    std::string plainText = "中文测试";
    std::string cipherText;
    ErrCode encryptResult = AesGcmHelper::Encrypt(plainText, cipherText);
    EXPECT_EQ(encryptResult, ERR_OK);
    
    std::string decryptedText;
    ErrCode decryptResult = AesGcmHelper::Decrypt(decryptedText, cipherText);
    EXPECT_EQ(decryptResult, ERR_OK);
    EXPECT_EQ(decryptedText, plainText);
}

/**
 * @tc.name: EncryptAndDecrypt_00002
 * @tc.desc: Test encrypt and decrypt roundtrip with numbers only
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, EncryptAndDecrypt_00002, Function | SmallTest | Level1)
{
    std::string plainText = "12345678901234567890";
    std::string cipherText;
    ErrCode encryptResult = AesGcmHelper::Encrypt(plainText, cipherText);
    EXPECT_EQ(encryptResult, ERR_OK);
    
    std::string decryptedText;
    ErrCode decryptResult = AesGcmHelper::Decrypt(decryptedText, cipherText);
    EXPECT_EQ(decryptResult, ERR_OK);
    EXPECT_EQ(decryptedText, plainText);
}

/**
 * @tc.name: EncryptAndDecrypt_00003
 * @tc.desc: Test encrypt and decrypt roundtrip with special symbols
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, EncryptAndDecrypt_00003, Function | SmallTest | Level1)
{
    std::string plainText = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
    std::string cipherText;
    ErrCode encryptResult = AesGcmHelper::Encrypt(plainText, cipherText);
    EXPECT_EQ(encryptResult, ERR_OK);
    
    std::string decryptedText;
    ErrCode decryptResult = AesGcmHelper::Decrypt(decryptedText, cipherText);
    EXPECT_EQ(decryptResult, ERR_OK);
    EXPECT_EQ(decryptedText, plainText);
}

/**
 * @tc.name: EncryptAndDecrypt_00004
 * @tc.desc: Test encrypt and decrypt roundtrip with whitespace
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, EncryptAndDecrypt_00004, Function | SmallTest | Level1)
{
    std::string plainText = "  \t\n\r  ";
    std::string cipherText;
    ErrCode encryptResult = AesGcmHelper::Encrypt(plainText, cipherText);
    EXPECT_EQ(encryptResult, ERR_OK);
    
    std::string decryptedText;
    ErrCode decryptResult = AesGcmHelper::Decrypt(decryptedText, cipherText);
    EXPECT_EQ(decryptResult, ERR_OK);
    EXPECT_EQ(decryptedText, plainText);
}

/**
 * @tc.name: EncryptAndDecrypt_00005
 * @tc.desc: Test encrypt and decrypt roundtrip with binary-like data
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, EncryptAndDecrypt_00005, Function | SmallTest | Level1)
{
    std::string plainText = "\x01\x02\x03\x04\x05\x06\x07\x08";
    std::string cipherText;
    ErrCode encryptResult = AesGcmHelper::Encrypt(plainText, cipherText);
    EXPECT_EQ(encryptResult, ERR_OK);
    
    std::string decryptedText;
    ErrCode decryptResult = AesGcmHelper::Decrypt(decryptedText, cipherText);
    EXPECT_EQ(decryptResult, ERR_OK);
    EXPECT_EQ(decryptedText, plainText);
}

/**
 * @tc.name: EncryptAesGcm_00001
 * @tc.desc: Test EncryptAesGcm with valid parameters
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, EncryptAesGcm_00001, Function | SmallTest | Level1)
{
    std::string plainText = "test";
    std::string cipherText;
    std::string key = "01234567890123456789012345678901";
    bool result = AesGcmHelper::EncryptAesGcm(plainText, cipherText, key);
    EXPECT_TRUE(result);
    EXPECT_TRUE(!cipherText.empty());
}

/**
 * @tc.name: EncryptAesGcm_00002
 * @tc.desc: Test EncryptAesGcm with 32-byte key
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, EncryptAesGcm_00002, Function | SmallTest | Level1)
{
    std::string plainText = "hello";
    std::string cipherText;
    std::string key(32, 'a');
    bool result = AesGcmHelper::EncryptAesGcm(plainText, cipherText, key);
    EXPECT_TRUE(result);
    EXPECT_TRUE(!cipherText.empty());
}

/**
 * @tc.name: DecryptAesGcm_00001
 * @tc.desc: Test DecryptAesGcm with valid parameters
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, DecryptAesGcm_00001, Function | SmallTest | Level1)
{
    std::string plainText = "test";
    std::string cipherText;
    std::string key = "01234567890123456789012345678901";
    
    bool encryptResult = AesGcmHelper::EncryptAesGcm(plainText, cipherText, key);
    EXPECT_TRUE(encryptResult);
    
    std::string decryptedText;
    bool decryptResult = AesGcmHelper::DecryptAesGcm(decryptedText, cipherText, key);
    EXPECT_TRUE(decryptResult);
    EXPECT_EQ(decryptedText, plainText);
}

/**
 * @tc.name: DecryptAesGcm_00002
 * @tc.desc: Test DecryptAesGcm with wrong key
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, DecryptAesGcm_00002, Function | SmallTest | Level1)
{
    std::string plainText = "test";
    std::string cipherText;
    std::string key1 = "01234567890123456789012345678901";
    std::string key2 = "98765432109876543210987654321098";
    
    bool encryptResult = AesGcmHelper::EncryptAesGcm(plainText, cipherText, key1);
    EXPECT_TRUE(encryptResult);
    
    std::string decryptedText;
    bool decryptResult = AesGcmHelper::DecryptAesGcm(decryptedText, cipherText, key2);
    EXPECT_FALSE(decryptResult);
}

/**
 * @tc.name: DecryptAesGcm_00003
 * @tc.desc: Test DecryptAesGcm with empty cipher text
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, DecryptAesGcm_00003, Function | SmallTest | Level1)
{
    std::string plainText;
    std::string cipherText = "";
    std::string key = "01234567890123456789012345678901";
    bool result = AesGcmHelper::DecryptAesGcm(plainText, cipherText, key);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: HexConversionRoundtrip_00001
 * @tc.desc: Test Byte2Hex and Hex2Byte conversion roundtrip
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, HexConversionRoundtrip_00001, Function | SmallTest | Level1)
{
    std::string originalBytes = "\x01\x23\x45\x67\x89\xab\xcd\xef";
    std::string hex = AesGcmHelper::Byte2Hex(originalBytes);
    std::string convertedBytes = AesGcmHelper::Hex2Byte(hex);
    EXPECT_EQ(convertedBytes, originalBytes);
}

/**
 * @tc.name: HexConversionRoundtrip_00002
 * @tc.desc: Test Byte2Hex and Hex2Byte conversion roundtrip with zero bytes
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, HexConversionRoundtrip_00002, Function | SmallTest | Level1)
{
    std::string originalBytes = "\x00\x00\x00\x00";
    std::string hex = AesGcmHelper::Byte2Hex(originalBytes);
    std::string convertedBytes = AesGcmHelper::Hex2Byte(hex);
    EXPECT_EQ(convertedBytes, originalBytes);
}

/**
 * @tc.name: HexConversionRoundtrip_00003
 * @tc.desc: Test Byte2Hex and Hex2Byte conversion roundtrip with max bytes
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, HexConversionRoundtrip_00003, Function | SmallTest | Level1)
{
    std::string originalBytes = "\xff\xff\xff\xff";
    std::string hex = AesGcmHelper::Byte2Hex(originalBytes);
    std::string convertedBytes = AesGcmHelper::Hex2Byte(hex);
    EXPECT_EQ(convertedBytes, originalBytes);
}

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

    ErrCode encryptResult = AesGcmHelper::Encrypt(test, temp);
    EXPECT_EQ(encryptResult, ERR_OK);
    
    ErrCode decryptResult = AesGcmHelper::Decrypt(result, temp);
    EXPECT_EQ(decryptResult, ERR_OK);
    
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

    ErrCode encryptResult = AesGcmHelper::Encrypt(test, temp);
    EXPECT_EQ(encryptResult, ERR_OK);
    
    ErrCode decryptResult = AesGcmHelper::Decrypt(result, temp);
    EXPECT_EQ(decryptResult, ERR_OK);
    
    ASSERT_EQ(result, test);
}

/**
 * @tc.name: MultipleEncryptDecrypt_00001
 * @tc.desc: Test multiple encrypt/decrypt operations produce different ciphertexts
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(AesGcmHelperUnitTest, MultipleEncryptDecrypt_00001, Function | SmallTest | Level1)
{
    std::string plainText = "same text";
    std::string cipherText1;
    std::string cipherText2;
    
    ErrCode result1 = AesGcmHelper::Encrypt(plainText, cipherText1);
    EXPECT_EQ(result1, ERR_OK);
    
    ErrCode result2 = AesGcmHelper::Encrypt(plainText, cipherText2);
    EXPECT_EQ(result2, ERR_OK);
    
    EXPECT_NE(cipherText1, cipherText2);
    
    std::string decrypted1;
    std::string decrypted2;
    
    ErrCode decryptResult1 = AesGcmHelper::Decrypt(decrypted1, cipherText1);
    EXPECT_EQ(decryptResult1, ERR_OK);
    EXPECT_EQ(decrypted1, plainText);
    
    ErrCode decryptResult2 = AesGcmHelper::Decrypt(decrypted2, cipherText2);
    EXPECT_EQ(decryptResult2, ERR_OK);
    EXPECT_EQ(decrypted2, plainText);
}

}
}