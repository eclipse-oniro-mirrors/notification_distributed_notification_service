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

#include "system_sound_helper.h"

#include "ans_log_wrapper.h"
#include "notifictaion_load_utils.h"
#include <memory>

namespace OHOS {
namespace Notification {
#ifdef PLAYER_FRAMEWORK_ENABLE
static const int32_t MAX_RETRY_TIME = 2;
static const uint64_t TASK_DELAY = 2 * 1000 * 1000;
static const std::string DYNAMIC_LIB_PATH = "libans_dynamic.z.so";
static const std::string REMOVE_TONC_FUNC_STR = "SystemSoundRemoveCustomizedTone";
static const std::string REMOVE_TONC_LIST_FUNC_STR = "SystemSoundRemoveCustomizedToneList";

using REMOVE_TONE_FUNC = bool (*)(std::string);
using REMOVE_TONE_LIST_FUNC = bool (*)(std::vector<std::string>);
#endif

ffrt::mutex SystemSoundHelper::instanceMutex_;
std::shared_ptr<SystemSoundHelper> SystemSoundHelper::instance_;

std::shared_ptr<SystemSoundHelper> SystemSoundHelper::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<ffrt::mutex> lock(instanceMutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<SystemSoundHelper>();
        }
    }
    return instance_;
}

void SystemSoundHelper::RemoveCustomizedTone(const std::string uri)
{
#ifndef PLAYER_FRAMEWORK_ENABLE
    ANS_LOGW("remove ringtone uri.");
    return;
#endif
    if (uri.empty()) {
        return;
    }

    std::function<void()> retryTask = [uri]() {
        std::unique_ptr<NotificationLoadUtils> loadUtils =
            std::make_unique<NotificationLoadUtils>(DYNAMIC_LIB_PATH);
        if (loadUtils == nullptr || !loadUtils->IsValid()) {
            ANS_LOGW("libans_dynamic not available");
            return;
        }
        REMOVE_TONE_FUNC removeToneFunc = (REMOVE_TONE_FUNC)loadUtils->GetProxyFunc(REMOVE_TONC_FUNC_STR);
        if (removeToneFunc == nullptr) {
            ANS_LOGW("SystemSoundRemoveCustomizedTone not available");
            return;
        }
        for (int32_t i = 0; i < MAX_RETRY_TIME; i++) {
            if (removeToneFunc(uri)) {
                break;
            }
        }
    };
    ffrt::submit(retryTask, ffrt::task_attr().delay(TASK_DELAY));
}

void SystemSoundHelper::RemoveCustomizedTone(sptr<NotificationRingtoneInfo> ringtoneInfo)
{
#ifndef PLAYER_FRAMEWORK_ENABLE
    ANS_LOGW("remove ringtone info.");
    return;
#endif
    if (ringtoneInfo == nullptr || (
        ringtoneInfo->GetRingtoneType() != NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL &&
        ringtoneInfo->GetRingtoneType() != NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE)) {
        return;
    }

    RemoveCustomizedTone(ringtoneInfo->GetRingtoneUri());
}

void SystemSoundHelper::RemoveCustomizedTones(std::vector<NotificationRingtoneInfo> ringtoneInfos)
{
#ifndef PLAYER_FRAMEWORK_ENABLE
    ANS_LOGW("remove ringtone info: %{public}zu.", ringtoneInfos.size());
    return;
#endif
    if (ringtoneInfos.empty()) {
        return;
    }
    
    std::vector<std::string> uris;
    for (auto& ringtoneInfo : ringtoneInfos) {
        if (ringtoneInfo.GetRingtoneType() == NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL ||
            ringtoneInfo.GetRingtoneType() == NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE) {
            uris.push_back(ringtoneInfo.GetRingtoneUri());
        }
    }

    if (uris.empty()) {
        return;
    }

    std::function<void()> retryTask = [uris]() {
        std::unique_ptr<NotificationLoadUtils> loadUtils =
            std::make_unique<NotificationLoadUtils>(DYNAMIC_LIB_PATH);
        if (loadUtils == nullptr || !loadUtils->IsValid()) {
            ANS_LOGW("libans_dynamic not available");
            return;
        }
        REMOVE_TONE_LIST_FUNC removeToneListFunc =
            (REMOVE_TONE_LIST_FUNC)loadUtils->GetProxyFunc(REMOVE_TONC_LIST_FUNC_STR);
        if (removeToneListFunc == nullptr) {
            ANS_LOGW("SystemSoundRemoveCustomizedToneList not available");
            return;
        }
        for (int32_t i = 0; i < MAX_RETRY_TIME; i++) {
            removeToneListFunc(uris);
        }
    };
    ffrt::submit(retryTask, ffrt::task_attr().delay(TASK_DELAY));
}
}  // namespace Notification
}  // namespace OHOS
