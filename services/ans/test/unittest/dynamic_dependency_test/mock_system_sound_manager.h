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

#ifndef BASE_ANS_TEST_UNITTEST_DYNAMIC_DEPENDENCY_TEST_MOCK_SYSTEM_SOUND_MANAGER_H
#define BASE_ANS_TEST_UNITTEST_DYNAMIC_DEPENDENCY_TEST_MOCK_SYSTEM_SOUND_MANAGER_H

#include <gmock/gmock.h>

#include "system_sound_manager.h"

namespace OHOS {
namespace Media {
class MockSystemSoundManager : public SystemSoundManager {
public:
    MockSystemSoundManager() = default;
    ~MockSystemSoundManager() = default;

    MOCK_METHOD(std::shared_ptr<RingtonePlayer>, GetRingtonePlayer,
        (const std::shared_ptr<AbilityRuntime::Context> &context, RingtoneType ringtoneType), ());
    MOCK_METHOD(std::shared_ptr<RingtonePlayer>, GetSpecificRingTonePlayer,
        (const std::shared_ptr<AbilityRuntime::Context> &context,
            const RingtoneType ringtoneType, std::string &ringtoneUri), ());
    MOCK_METHOD(int32_t, SetRingtoneUri, (const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::string &uri, RingtoneType ringtoneType), ());
    MOCK_METHOD(std::string, GetRingtoneUri,
        (const std::shared_ptr<AbilityRuntime::Context> &context, RingtoneType ringtoneType), ());
    MOCK_METHOD(ToneAttrs, GetCurrentRingtoneAttribute, (RingtoneType ringtoneType), ());
    MOCK_METHOD(std::shared_ptr<SystemTonePlayer>, GetSystemTonePlayer,
        (const std::shared_ptr<AbilityRuntime::Context> &context, SystemToneType systemToneType), ());
    MOCK_METHOD(int32_t, SetSystemToneUri, (const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::string &uri, SystemToneType systemToneType), ());
    MOCK_METHOD(std::string, GetSystemToneUri,
        (const std::shared_ptr<AbilityRuntime::Context> &context, SystemToneType systemToneType), ());
    MOCK_METHOD(std::shared_ptr<ToneAttrs>, GetDefaultRingtoneAttrs,
        (const std::shared_ptr<AbilityRuntime::Context> &context, RingtoneType ringtoneType), ());
    MOCK_METHOD(std::vector<std::shared_ptr<ToneAttrs>>, GetRingtoneAttrList,
        (const std::shared_ptr<AbilityRuntime::Context> &context, RingtoneType ringtoneType), ());
    MOCK_METHOD(std::shared_ptr<ToneAttrs>, GetDefaultSystemToneAttrs,
        (const std::shared_ptr<AbilityRuntime::Context> &context, SystemToneType systemtoneType), ());
    MOCK_METHOD(std::vector<std::shared_ptr<ToneAttrs>>, GetSystemToneAttrList,
        (const std::shared_ptr<AbilityRuntime::Context> &context, SystemToneType systemToneType), ());
    MOCK_METHOD(int32_t, SetAlarmToneUri,
        (const std::shared_ptr<AbilityRuntime::Context> &context, const std::string &uri), ());
    MOCK_METHOD(std::string, GetAlarmToneUri, (const std::shared_ptr<AbilityRuntime::Context> &context), ());
    MOCK_METHOD(std::shared_ptr<ToneAttrs>, GetDefaultAlarmToneAttrs,
        (const std::shared_ptr<AbilityRuntime::Context> &context), ());
    MOCK_METHOD(std::vector<std::shared_ptr<ToneAttrs>>, GetAlarmToneAttrList,
        (const std::shared_ptr<AbilityRuntime::Context> &context), ());
    MOCK_METHOD(int32_t, OpenAlarmTone,
        (const std::shared_ptr<AbilityRuntime::Context> &context, const std::string &uri), ());
    MOCK_METHOD(int32_t, Close, (const int32_t &fd), ());
    MOCK_METHOD(std::string, AddCustomizedToneByExternalUri, (const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::shared_ptr<ToneAttrs> &toneAttrs, const std::string &externalUri), ());
    MOCK_METHOD(std::string, AddCustomizedToneByFd, (const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::shared_ptr<ToneAttrs> &toneAttrs, const int32_t &fd), ());
    MOCK_METHOD(std::string, AddCustomizedToneByFdAndOffset, (const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::shared_ptr<ToneAttrs> &toneAttrs, ParamsForAddCustomizedTone &paramsForAddCustomizedTone), ());
    MOCK_METHOD(int32_t, RemoveCustomizedTone,
        (const std::shared_ptr<AbilityRuntime::Context> &context, const std::string &uri), ());
    MOCK_METHOD((std::vector<std::pair<std::string, SystemSoundError>>), RemoveCustomizedToneList,
        (const std::vector<std::string> &uriList, SystemSoundError &errCode), ());
    MOCK_METHOD(int32_t, GetToneHapticsSettings, (const std::shared_ptr<AbilityRuntime::Context> &context,
        ToneHapticsType toneHapticsType, ToneHapticsSettings &settings), ());
    MOCK_METHOD(int32_t, SetToneHapticsSettings, (const std::shared_ptr<AbilityRuntime::Context> &context,
        ToneHapticsType toneHapticsType, const ToneHapticsSettings &settings), ());
    MOCK_METHOD(int32_t, GetToneHapticsList, (const std::shared_ptr<AbilityRuntime::Context> &context, bool isSynced,
        std::vector<std::shared_ptr<ToneHapticsAttrs>> &toneHapticsAttrsArray), ());
    MOCK_METHOD(int32_t, GetHapticsAttrsSyncedWithTone, (const std::shared_ptr<AbilityRuntime::Context> &context,
        const std::string &toneUri, std::shared_ptr<ToneHapticsAttrs> &toneHapticsAttrs), ());
    MOCK_METHOD(int32_t, OpenToneHaptics,
        (const std::shared_ptr<AbilityRuntime::Context> &context, const std::string &hapticsUri), ());
    MOCK_METHOD(int32_t, OpenToneUri,
        (const std::shared_ptr<AbilityRuntime::Context> &context, const std::string &uri, int32_t toneType), ());
    MOCK_METHOD((std::vector<std::tuple<std::string, int64_t, SystemSoundError>>), OpenToneList,
        (const std::vector<std::string> &uriList, SystemSoundError &errCode), ());
    MOCK_METHOD(std::vector<ToneInfo>, GetCurrentToneInfos, (), ());
};

} // Media
} // OHOS

#endif
