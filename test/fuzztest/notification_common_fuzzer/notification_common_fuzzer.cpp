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

#include "ans_convert_enum.h"
#include "aes_gcm_helper.h"
#include "file_utils.h"
#include "notification_app_privileges.h"
#include "notification_ringtone_info.h"
#include "screen_manager_helper.h"
#include "system_sound_helper.h"

namespace OHOS {
namespace Notification {
    namespace {
        constexpr uint8_t CONTENT_TYPE_C_COUNT = 10;
        constexpr uint8_t CONTENT_TYPE_JS_COUNT = 8;
        constexpr uint8_t SLOT_TYPE_C_COUNT = 9;
        constexpr uint8_t SLOT_TYPE_JS_COUNT = 8;
        constexpr uint8_t SLOT_LEVEL_COUNT = 5;
        constexpr uint8_t LIVE_VIEW_STATUS_COUNT = 7;
        constexpr uint8_t LIVE_VIEW_TYPES_COUNT = 4;
        constexpr uint8_t MONITOR_EVENT_COUNT = 3;
        constexpr uint8_t COORD_TYPE_COUNT = 3;
        constexpr uint8_t TRIGGER_TYPE_COUNT = 2;
        constexpr uint8_t DND_TYPE_COUNT = 4;
        constexpr uint8_t REMIND_TYPE_COUNT = 3;
        constexpr size_t FUZZ_STRING_TINY_LEN = 8;
        constexpr size_t FUZZ_STRING_MAX_LEN = 64;
        constexpr size_t HEX_CHARS_PER_BYTE = 2;
        constexpr size_t OVER_MAX_CIPHER_LEN = (16 * 1024 * 1024) + 8;
    }

    bool TestAesGcmEncryptDecrypt(FuzzedDataProvider *fdp)
    {
        std::string plainText = fdp->ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN);
        std::string cipherText;
        ErrCode encResult = AesGcmHelper::Encrypt(plainText, cipherText);
        std::string decryptedText;
        if (encResult == ERR_OK) {
            AesGcmHelper::Decrypt(decryptedText, cipherText);
            AesGcmHelper::Decrypt(decryptedText, cipherText.substr(0, cipherText.size() - HEX_CHARS_PER_BYTE));
            AesGcmHelper::Decrypt(decryptedText, "zz" + cipherText);
        }
        AesGcmHelper::Encrypt(std::string(), cipherText);
        std::string emptyDecrypted;
        AesGcmHelper::Decrypt(emptyDecrypted, std::string());
        // "abc"/"zz"/"0011" target the hex-decode branches inside Decrypt:
        // odd length, invalid hex chars, and valid hex but too short
        AesGcmHelper::Decrypt(emptyDecrypted, "abc");
        AesGcmHelper::Decrypt(emptyDecrypted, "zz");
        AesGcmHelper::Decrypt(emptyDecrypted, "0011");
        AesGcmHelper::Decrypt(emptyDecrypted, "0123456789abcdefABCDEF");
        std::string longCipher(OVER_MAX_CIPHER_LEN, 'a');
        AesGcmHelper::Decrypt(emptyDecrypted, longCipher);
        return true;
    }

    bool TestContentAndSlotEnumConvert(FuzzedDataProvider *fdp)
    {
        NotificationNapi::ContentType jsContentType;
        NotificationContent::Type cContentType = static_cast<NotificationContent::Type>(
            fdp->ConsumeIntegral<uint8_t>() % CONTENT_TYPE_C_COUNT);
        NotificationNapi::AnsEnumUtil::ContentTypeCToJS(cContentType, jsContentType);
        NotificationNapi::AnsEnumUtil::ContentTypeJSToC(
            static_cast<NotificationNapi::ContentType>(fdp->ConsumeIntegral<uint8_t>() % CONTENT_TYPE_JS_COUNT),
            cContentType);

        NotificationNapi::SlotType jsSlotType;
        NotificationConstant::SlotType cSlotType = static_cast<NotificationConstant::SlotType>(
            fdp->ConsumeIntegral<uint8_t>() % SLOT_TYPE_C_COUNT);
        NotificationNapi::AnsEnumUtil::SlotTypeCToJS(cSlotType, jsSlotType);
        NotificationNapi::AnsEnumUtil::SlotTypeJSToC(
            static_cast<NotificationNapi::SlotType>(fdp->ConsumeIntegral<uint8_t>() % SLOT_TYPE_JS_COUNT),
            cSlotType);

        NotificationNapi::SlotLevel jsSlotLevel;
        NotificationSlot::NotificationLevel cSlotLevel = static_cast<NotificationSlot::NotificationLevel>(
            fdp->ConsumeIntegral<uint8_t>() % SLOT_LEVEL_COUNT);
        NotificationNapi::AnsEnumUtil::SlotLevelCToJS(cSlotLevel, jsSlotLevel);
        NotificationNapi::AnsEnumUtil::SlotLevelJSToC(
            static_cast<NotificationNapi::SlotLevel>(fdp->ConsumeIntegral<uint8_t>() % SLOT_LEVEL_COUNT),
            cSlotLevel);
        return true;
    }

    bool TestLiveViewEnumConvert(FuzzedDataProvider *fdp)
    {
        NotificationNapi::LiveViewStatus jsLiveViewStatus;
        NotificationLiveViewContent::LiveViewStatus cLiveViewStatus =
            static_cast<NotificationLiveViewContent::LiveViewStatus>(
                fdp->ConsumeIntegral<uint8_t>() % LIVE_VIEW_STATUS_COUNT);
        NotificationNapi::AnsEnumUtil::LiveViewStatusJSToC(
            static_cast<NotificationNapi::LiveViewStatus>(fdp->ConsumeIntegral<uint8_t>() % LIVE_VIEW_STATUS_COUNT),
            cLiveViewStatus);
        NotificationNapi::AnsEnumUtil::LiveViewStatusCToJS(cLiveViewStatus, jsLiveViewStatus);

        NotificationNapi::LiveViewTypes jsLiveViewTypes;
        NotificationLocalLiveViewContent::LiveViewTypes cLiveViewTypes =
            static_cast<NotificationLocalLiveViewContent::LiveViewTypes>(
                fdp->ConsumeIntegral<uint8_t>() % LIVE_VIEW_TYPES_COUNT);
        NotificationNapi::AnsEnumUtil::LiveViewTypesJSToC(
            static_cast<NotificationNapi::LiveViewTypes>(fdp->ConsumeIntegral<uint8_t>() % LIVE_VIEW_TYPES_COUNT),
            cLiveViewTypes);
        NotificationNapi::AnsEnumUtil::LiveViewTypesCToJS(cLiveViewTypes, jsLiveViewTypes);
        return true;
    }

    bool TestMiscEnumConvert(FuzzedDataProvider *fdp)
    {
        NotificationConstant::MonitorEvent cMonitorEvent;
        NotificationNapi::AnsEnumUtil::MonitorEventJSToC(
            static_cast<NotificationNapi::MonitorEvent>(fdp->ConsumeIntegral<uint8_t>() % MONITOR_EVENT_COUNT),
            cMonitorEvent);
        NotificationConstant::CoordinateSystemType cCoordType;
        NotificationNapi::AnsEnumUtil::CoordinateSystemTypeJSToC(
            static_cast<NotificationNapi::CoordinateSystemType>(fdp->ConsumeIntegral<uint8_t>() % COORD_TYPE_COUNT),
            cCoordType);
        NotificationConstant::TriggerType cTriggerType;
        NotificationNapi::AnsEnumUtil::TriggerTypeJSToC(
            static_cast<NotificationNapi::TriggerType>(fdp->ConsumeIntegral<uint8_t>() % TRIGGER_TYPE_COUNT),
            cTriggerType);

        NotificationNapi::DoNotDisturbType jsDndType;
        NotificationConstant::DoNotDisturbType cDndType = static_cast<NotificationConstant::DoNotDisturbType>(
            fdp->ConsumeIntegral<uint8_t>() % DND_TYPE_COUNT);
        NotificationNapi::AnsEnumUtil::DoNotDisturbTypeCToJS(cDndType, jsDndType);
        NotificationNapi::AnsEnumUtil::DoNotDisturbTypeJSToC(
            static_cast<NotificationNapi::DoNotDisturbType>(
                fdp->ConsumeIntegral<uint8_t>() % DND_TYPE_COUNT), cDndType);

        NotificationNapi::DeviceRemindType jsRemindType;
        NotificationNapi::AnsEnumUtil::DeviceRemindTypeCToJS(
            static_cast<NotificationConstant::RemindType>(fdp->ConsumeIntegral<uint8_t>() % REMIND_TYPE_COUNT),
            jsRemindType);
        NotificationNapi::SourceType jsSourceType;
        NotificationNapi::AnsEnumUtil::SourceTypeCToJS(
            static_cast<NotificationConstant::SourceType>(fdp->ConsumeIntegral<uint8_t>() % REMIND_TYPE_COUNT),
            jsSourceType);

        NotificationNapi::SubscribeType jsSubscribeType;
        NotificationConstant::SubscribeType cSubscribeType;
        NotificationNapi::AnsEnumUtil::SubscribeTypeJSToC(
            static_cast<NotificationNapi::SubscribeType>(fdp->ConsumeBool() ? 0 : 1), cSubscribeType);
        NotificationNapi::AnsEnumUtil::SubscribeTypeCToJS(cSubscribeType, jsSubscribeType);

        int32_t reason = 0;
        NotificationNapi::AnsEnumUtil::ReasonCToJS(fdp->ConsumeIntegral<int32_t>(), reason);
        return true;
    }

    bool TestAppPrivilegesBoundaries(FuzzedDataProvider *fdp)
    {
        // flag-string boundaries: every bit position of the 4 privilege flags
        static const std::string flagStrings[] = {
            "", "0", "1", "11", "111", "1111", "11111", "0000", "00000",
            "0101", "1010", "abcd", "\xe4\xbd\xa0\xe5\xa5\xbd", "\x01\x02"
        };
        for (const std::string &flagStr : flagStrings) {
            NotificationAppPrivileges privileges(flagStr);
            privileges.IsLiveViewEnabled();
            privileges.IsBannerEnabled();
            privileges.IsReminderEnabled();
            privileges.IsDistributedReplyEnabled();
        }
        NotificationAppPrivileges fuzzed(fdp->ConsumeRandomLengthString(FUZZ_STRING_TINY_LEN));
        fuzzed.IsLiveViewEnabled();
        fuzzed.IsBannerEnabled();
        fuzzed.IsReminderEnabled();
        fuzzed.IsDistributedReplyEnabled();
        return true;
    }

    bool TestFileUtils(FuzzedDataProvider *fdp)
    {
        std::vector<nlohmann::json> roots;
        FileUtils::GetJsonByFilePath("", roots);
        FileUtils::GetJsonByFilePath("/proc/self/nonexistent_dir/", roots);
        FileUtils::GetJsonByFilePath(fdp->ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN).c_str(), roots);
        return true;
    }

    bool TestSingletonEntries(FuzzedDataProvider *fdp)
    {
        auto screenHelper = ScreenManagerHelper::GetInstance();
        if (screenHelper != nullptr) {
            screenHelper->GetScreenPower();
        }
        auto soundHelper = SystemSoundHelper::GetInstance();
        if (soundHelper == nullptr) {
            return true;
        }
        soundHelper->RemoveCustomizedTone(fdp->ConsumeRandomLengthString());
        soundHelper->RemoveCustomizedTone(std::string());
        sptr<NotificationRingtoneInfo> nullRingtone = nullptr;
        soundHelper->RemoveCustomizedTone(nullRingtone);
        sptr<NotificationRingtoneInfo> systemRingtone = new NotificationRingtoneInfo();
        if (systemRingtone != nullptr) {
            systemRingtone->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_SYSTEM);
            soundHelper->RemoveCustomizedTone(systemRingtone);
        }
        sptr<NotificationRingtoneInfo> localRingtone = new NotificationRingtoneInfo();
        if (localRingtone != nullptr) {
            localRingtone->SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL);
            localRingtone->SetRingtoneUri(fdp->ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN));
            soundHelper->RemoveCustomizedTone(localRingtone);
        }
        std::vector<NotificationRingtoneInfo> emptyRingtoneInfos;
        soundHelper->RemoveCustomizedTones(emptyRingtoneInfos);
        std::vector<NotificationRingtoneInfo> mixedRingtoneInfos;
        NotificationRingtoneInfo online;
        online.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE);
        online.SetRingtoneUri(fdp->ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN));
        NotificationRingtoneInfo none;
        none.SetRingtoneType(NotificationConstant::RingtoneType::RINGTONE_TYPE_NONE);
        mixedRingtoneInfos.push_back(online);
        mixedRingtoneInfos.push_back(none);
        soundHelper->RemoveCustomizedTones(mixedRingtoneInfos);
        return true;
    }

    bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
    {
        TestAesGcmEncryptDecrypt(fdp);
        TestContentAndSlotEnumConvert(fdp);
        TestLiveViewEnumConvert(fdp);
        TestMiscEnumConvert(fdp);
        TestAppPrivilegesBoundaries(fdp);
        TestFileUtils(fdp);
        TestSingletonEntries(fdp);
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
