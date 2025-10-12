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
#include "distributed_data_define.h"
#ifdef PLAYER_FRAMEWORK_ENABLE
#include "media_errors.h"
#endif

namespace OHOS {
namespace Notification {
SystemSoundHelper::SystemSoundHelper()
{
}

SystemSoundHelper::~SystemSoundHelper()
{
}

#ifdef PLAYER_FRAMEWORK_ENABLE
void SystemSoundHelper::Connect()
{
    if (systemSoundClient_ == nullptr) {
        systemSoundClient_ = Media::SystemSoundManagerFactory::CreateSystemSoundManager();
    }
}

void SystemSoundHelper::RemoveCustomizedTone(sptr<NotificationRingtoneInfo> ringtoneInfo)
{
    if (ringtoneInfo == nullptr || (
        ringtoneInfo->GetRingtoneType() != NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL &&
        ringtoneInfo->GetRingtoneType() != NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE)) {
        return;
    }

    std::lock_guard<ffrt::mutex> lock(lock_);
    Connect();
    if (systemSoundClient_ == nullptr) {
        ANS_LOGW("Get system clint failed.");
        return;
    }
    int32_t result = systemSoundClient_->RemoveCustomizedTone(nullptr, ringtoneInfo->GetRingtoneUri());
    ANS_LOGI("Remove Customized tone, uri: %{public}s, result: %{public}d",
        StringAnonymous(ringtoneInfo->GetRingtoneUri()).c_str(), result);
}

void SystemSoundHelper::RemoveCustomizedTones(std::vector<NotificationRingtoneInfo> ringtoneInfos)
{
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
        ANS_LOGI("Empty local or online info.");
        return;
    }

    std::lock_guard<ffrt::mutex> lock(lock_);
    Connect();
    if (systemSoundClient_ == nullptr) {
        ANS_LOGW("Get system clint failed.");
        return;
    }

    Media::SystemSoundError error = Media::SystemSoundError::ERROR_OK;
    auto results = systemSoundClient_->RemoveCustomizedToneList(uris, error);
    for (auto item : results) {
        ANS_LOGI("Remove Customized tone, uri: %{public}s, result: %{public}d",
            StringAnonymous(item.first).c_str(), item.second);
    }
}
#else
void SystemSoundHelper::RemoveCustomizedTone(sptr<NotificationRingtoneInfo> ringtoneInfo)
{
    ANS_LOGW("remove ringtone info.");
}

void SystemSoundHelper::RemoveCustomizedTones(std::vector<NotificationRingtoneInfo> ringtoneInfos)
{
    ANS_LOGW("remove ringtone info: %{public}zu.", ringtoneInfos.size());
}
#endif
}  // namespace Notification
}  // namespace OHOS
