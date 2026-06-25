/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "notification_common_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "aes_gcm_helper.h"
#include "notification_app_privileges.h"
#include "screen_manager_helper.h"
#include "system_sound_helper.h"

namespace OHOS {
namespace Notification {
    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        std::string plainText = fdp->ConsumeRandomLengthString();
        std::string cipherText;
        AesGcmHelper::Encrypt(plainText, cipherText);
        std::string decryptedText;
        AesGcmHelper::Decrypt(decryptedText, cipherText);

        std::string otherPlain = fdp->ConsumeRandomLengthString();
        std::string otherCipher;
        AesGcmHelper::Encrypt(otherPlain, otherCipher);
        AesGcmHelper::Decrypt(decryptedText, otherCipher);

        NotificationAppPrivileges priv(fdp->ConsumeRandomLengthString());
        priv.IsLiveViewEnabled();
        priv.IsBannerEnabled();
        priv.IsReminderEnabled();
        priv.IsDistributedReplyEnabled();

        NotificationAppPrivileges priv2(fdp->ConsumeRandomLengthString());
        priv2.IsLiveViewEnabled();
        priv2.IsReminderEnabled();

        ScreenManagerHelper::GetInstance()->GetScreenPower();

        SystemSoundHelper::GetInstance()->RemoveCustomizedTone(fdp->ConsumeRandomLengthString());

        return true;
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::Notification::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
