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

static const int32_t REMOVE_SUCCESS_COUNT = 1;
static const uint64_t TASK_DELAY = 2 * 1000 * 1000;

void SystemSoundHelper::Connect()
{
    if (systemSoundClient_ == nullptr) {
        systemSoundClient_ = Media::SystemSoundManagerFactory::CreateSystemSoundManager();
    }
}

int32_t SystemSoundHelper::InvokeRemoveCustomizedTone(const std::string uri, bool retry)
{
    if (uri.empty()) {
        return REMOVE_SUCCESS_COUNT;
    }

    std::lock_guard<ffrt::mutex> lock(lock_);
    Connect();
    if (systemSoundClient_ == nullptr) {
        ANS_LOGW("Get system clint failed.");
        return -1;
    }
    int32_t result = systemSoundClient_->RemoveCustomizedTone(nullptr, uri);
    ANS_LOGI("Remove Customized tone %{public}d, uri: %{public}s, result: %{public}d",
        retry, uri.c_str(), result);
    return result;
}

void SystemSoundHelper::RemoveCustomizedTone(const std::string uri)
{
    if (InvokeRemoveCustomizedTone(uri) != REMOVE_SUCCESS_COUNT) {
        std::function<void()> retryTask = [uri]() {
            SystemSoundHelper::GetInstance()->InvokeRemoveCustomizedTone(uri, true);
        };
        ffrt::submit(retryTask, ffrt::task_attr().delay(TASK_DELAY));
    }
}

void SystemSoundHelper::RemoveCustomizedTone(sptr<NotificationRingtoneInfo> ringtoneInfo)
{
    if (ringtoneInfo == nullptr || (
        ringtoneInfo->GetRingtoneType() != NotificationConstant::RingtoneType::RINGTONE_TYPE_LOCAL &&
        ringtoneInfo->GetRingtoneType() != NotificationConstant::RingtoneType::RINGTONE_TYPE_ONLINE)) {
        return;
    }

    RemoveCustomizedTone(ringtoneInfo->GetRingtoneUri());
}

std::vector<std::pair<std::string, int32_t>> SystemSoundHelper::InvokeRemoveCustomizedTones(
    const std::vector<std::string> uris, bool retry)
{
    std::vector<std::pair<std::string, int32_t>> invockResults;
    if (uris.empty()) {
        ANS_LOGI("Empty local or online info.");
        return invockResults;
    }

    std::lock_guard<ffrt::mutex> lock(lock_);
    Connect();
    if (systemSoundClient_ == nullptr) {
        ANS_LOGW("Get system clint failed.");
        return invockResults;
    }

    Media::SystemSoundError error = Media::SystemSoundError::ERROR_OK;
    auto results = systemSoundClient_->RemoveCustomizedToneList(uris, error);
    for (auto item : results) {
        ANS_LOGI("Remove Customized tone %{public}d, uri: %{public}s, result: %{public}d",
            retry, item.first.c_str(), item.second);
        invockResults.push_back(std::make_pair(item.first, item.second));
    }
    return invockResults;
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

    auto results = InvokeRemoveCustomizedTones(uris);
    if (results.empty()) {
        return;
    }

    std::vector<std::string> failedUris;
    for (auto& item : results) {
        if (item.second != Media::SystemSoundError::ERROR_OK) {
            failedUris.push_back(item.first);
        }
    }

    if (!failedUris.empty()) {
        std::function<void()> retryTask = [failedUris]() {
            SystemSoundHelper::GetInstance()->InvokeRemoveCustomizedTones(failedUris, true);
        };
        ffrt::submit(retryTask, ffrt::task_attr().delay(TASK_DELAY));
    }
}
#else
void SystemSoundHelper::RemoveCustomizedTone(const std::string uri)
{
    ANS_LOGW("remove ringtone uri.");
}

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
