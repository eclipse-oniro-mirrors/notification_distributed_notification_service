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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_AES_GCM_HELPER_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_AES_GCM_HELPER_H
#include <string>

#include "errors.h"
#include "ans_inner_errors.h"

namespace OHOS {
namespace Notification {
class AesGcmHelper final {
public:
    static ErrCode Encrypt(const std::string &plainText, std::string &cipherText);
    static ErrCode Decrypt(std::string &plainText, const std::string &cipherText);

private:
    static bool EncryptAesGcm(const std::string &plainText, std::string &cipherText, std::string &key);
    static bool DecryptAesGcm(std::string &plainText, const std::string &cipherText, std::string &key);
    static bool GenerateKey(std::string &key);
    static std::string Byte2Hex(const std::string &bytes);
    static std::string Hex2Byte(const std::string &hex);
    static unsigned char HexChar2Byte(const char &hexCh);
};
}  // namespace OHOS::Notification
}  // namespace OHOS
#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_AES_GCM_HELPER_H
