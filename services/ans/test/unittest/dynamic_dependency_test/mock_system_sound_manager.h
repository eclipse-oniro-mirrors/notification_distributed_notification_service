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
#include <memory>
#include <vector>
#include <string>

namespace OHOS {
namespace Media {

class MockSystemSoundManager : public SystemSoundManager {
public:
    MOCK_METHOD2(GetRingtonePlayer,
        std::shared_ptr<RingtonePlayer>,
        (const std::shared_ptr<AbilityRuntime::Context>&, RingtoneType),
        (override));
    MOCK_METHOD2(GetSpecificRingTonePlayer,
        std::shared_ptr<RingtonePlayer>,
        (const std::shared_ptr<AbilityRuntime::Context>&, RingtoneType, std::string&),
        (override));
    MOCK_METHOD3(SetRingtoneUri,
        int32_t,
        (const std::shared_ptr<AbilityRuntime::Context>&, const std::string&, RingtoneType),
        (override));
    MOCK_METHOD2(GetRingtoneUri,
        std::string,
        (const std::shared_ptr<AbilityRuntime::Context>&, RingtoneType),
        (override));
    MOCK_METHOD1(GetCurrentRingtoneAttribute,
        ToneAttrs,
        (RingtoneType),
        (override));
    MOCK_METHOD2(GetSystemTonePlayer,
        std::shared_ptr<SystemTonePlayer>,
        (const std::shared_ptr<AbilityRuntime::Context>&, SystemToneType),
        (override));
    MOCK_METHOD3(SetSystemToneUri,
        int32_t,
        (const std::shared_ptr<AbilityRuntime::Context>&, const std::string&, SystemToneType),
        (override));
    MOCK_METHOD2(GetSystemToneUri,
        std::string,
        (const std::shared_ptr<AbilityRuntime::Context>&, SystemToneType),
        (override));
    MOCK_METHOD2(GetDefaultRingtoneAttrs,
        std::shared_ptr<ToneAttrs>,
        (const std::shared_ptr<AbilityRuntime::Context>&, RingtoneType),
        (override));
    MOCK_METHOD2(GetRingtoneAttrList,
        std::vector<std::shared_ptr<ToneAttrs>>,
        (const std::shared_ptr<AbilityRuntime::Context>&, RingtoneType),
        (override));
    MOCK_METHOD2(GetDefaultSystemToneAttrs,
        std::shared_ptr<ToneAttrs>,
        (const std::shared_ptr<AbilityRuntime::Context>&, SystemToneType),
        (override));
    MOCK_METHOD2(GetSystemToneAttrList,
        std::vector<std::shared_ptr<ToneAttrs>>,
        (const std::shared_ptr<AbilityRuntime::Context>&, SystemToneType),
        (override));
    MOCK_METHOD2(SetAlarmToneUri,
        int32_t,
        (const std::shared_ptr<AbilityRuntime::Context>&&),
        (override));
    MOCK_METHOD1(GetAlarmToneUri,
        std::string,
        (const std::shared_ptr<AbilityRuntime::Context>&),
        (override));
    MOCK_METHOD1(GetDefaultAlarmToneAttrs,
        std::shared_ptr<ToneAttrs>,
        (const std::shared_ptr<AbilityRuntime::Context>&),
        (override));
    MOCK_METHOD1(GetAlarmToneAttrList,
        std::vector<std::shared_ptr<ToneAttrs>>,
        (const std::shared_ptr<AbilityRuntime::Context>&),
        (override));
    MOCK_METHOD2(OpenAlarmTone,
        int32_t,
        (const std::shared_ptr<AbilityRuntime::Context>&, const std::string&),
        (override));
    MOCK_METHOD1(Close,
        int32_t,
        (const int32_t&),
        (override));
    MOCK_METHOD3(AddCustomizedToneByExternalUri,
        std::string,
        (const std::shared_ptr<AbilityRuntime::Context>&, const std::shared_ptr<ToneAttrs>&, const std::string&),
        (override));
    MOCK_METHOD3(AddCustomizedToneByFd,
        std::string,
        (const std::shared_ptr<AbilityRuntime::Context>&, const std::shared_ptr<ToneAttrs>&, const int32_t&),
        (override));
    MOCK_METHOD3(AddCustomizedToneByFdAndOffset,
        std::string,
        (const std::shared_ptr<AbilityRuntime::Context>&,
            const std::shared_ptr<ToneAttrs>&, ParamsForAddCustomizedTone&),
        (override));
    MOCK_METHOD2(RemoveCustomizedTone,
        int32_t,
        (const std::shared_ptr<AbilityRuntime::Context>&, const std::string&),
        (override));
    MOCK_METHOD2(RemoveCustomizedToneList,
        std::vector<std::pair<std::string, SystemSoundError>>,
        (const std::vector<std::string>&, SystemSoundError&),
        (override));
    MOCK_METHOD3(GetToneHapticsSettings,
        int32_t,
        (const std::shared_ptr<AbilityRuntime::Context>&, ToneHapticsType, ToneHapticsSettings&),
        (override));
    MOCK_METHOD3(SetToneHapticsSettings,
        int32_t,
        (const std::shared_ptr<AbilityRuntime::ContextContext>&, ToneHapticsType, const ToneHapticsSettings&),
        (override));
    MOCK_METHOD3(GetToneHapticsList,
        int32_t,
        (const std::shared_ptr<AbilityRuntime::Context>&, bool, std::vector<std::shared_ptr<ToneHapticsAttrs>>&),
        (override));
    MOCK_METHOD3(GetHapticsAttrsSyncedWithTone,
        int32_t,
        (const std::shared_ptr<AbilityRuntime::Context>&, const std::string&, std::shared_ptr<ToneHapticsAttrs>&),
        (override));
    MOCK_METHOD2(OpenToneHaptics,
        int32_t,
        (const std::shared_ptr<AbilityRuntime::Context>&, const std::string&),
        (override));
    MOCK_METHOD3(OpenToneUri,
        int32_t,
        (const std::shared_ptr<AbilityRuntime::Context>&, const std::string&, int32_t),
        (override));
    MOCK_METHOD2(OpenToneList,
        std::vector<std::tuple<std::string, int64_t, SystemSoundError>>,
        (const std::vector<std::string>&, SystemSoundError&),
        (override));
    MOCK_METHOD0(GetCurrentToneInfos,
        std::vector<ToneInfo>,
        (override));
};

}
}
#endif
