/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "notification_liveview_utils.h"

#include <dlfcn.h>
#include "ans_log_wrapper.h"
#include "advanced_notification_inline.h"
#include "notification_preferences.h"
#include "liveview_all_scenarios_extension_wrapper.h"

namespace OHOS {
namespace Notification {

NotificationLiveViewUtils& NotificationLiveViewUtils::GetInstance()
{
    static NotificationLiveViewUtils notificationLiveViewUtils;
    return notificationLiveViewUtils;
}

std::string NotificationLiveViewUtils::AddLiveViewCheckData(std::shared_ptr<LiveViewCheckParam>& param)
{
    std::string requestId = std::to_string(GetCurrentTime()) + std::to_string(param->bundlesName.size());
    std::lock_guard<ffrt::mutex> lock(dataMutex);
    checkData[requestId] = param;
    return requestId;
}

void NotificationLiveViewUtils::EraseLiveViewCheckData(const std::string& requestId)
{
    std::lock_guard<ffrt::mutex> lock(dataMutex);
    checkData.erase(requestId);
}

bool NotificationLiveViewUtils::GetLiveViewCheckData(const std::string& requestId,
    std::shared_ptr<LiveViewCheckParam>& data)
{
    std::lock_guard<ffrt::mutex> lock(dataMutex);
    if (checkData.find(requestId) == checkData.end()) {
        return false;
    }
    data = checkData[requestId];
    return true;
}

bool NotificationLiveViewUtils::CheckLiveViewConfigByBundle(const std::string& bundleName,
    const std::string& event)
{
    int32_t userId = SUBSCRIBE_USER_INIT;
    if (OsAccountManagerHelper::GetInstance().GetCurrentActiveUserId(userId) != ERR_OK) {
        ANS_LOGE("Current user acquisition failed");
        userId = DEFAULT_USER_ID;
    }

    bool configEnable = false;
    if (LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->CheckLiveViewConfig(bundleName, event,
        userId, configEnable) != ERR_OK) {
        return false;
    }
    return configEnable;
}

bool NotificationLiveViewUtils::CheckLiveViewForBundle(const sptr<NotificationRequest>& request)
{
    if (request == nullptr || !request->IsCommonLiveView()) {
        return false;
    }

    std::string bundleName;
    if (request->IsAgentNotification()) {
        bundleName = request->GetOwnerBundleName();
    } else {
        bundleName = request->GetCreatorBundleName();
    }

    std::string event;
    auto content = request->GetContent()->GetNotificationContent();
    auto liveViewContent = std::static_pointer_cast<NotificationLiveViewContent>(content);
    std::shared_ptr<AAFwk::WantParams> extroInfo = liveViewContent->GetExtraInfo();
    if (extroInfo != nullptr && extroInfo->HasParam("event")) {
        event = extroInfo->GetStringParam("event");
    }

    bool enable = false;
    if (LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->CheckLiveViewConfig(bundleName, event,
        DEFAULT_USER_ID, enable) != ERR_OK) {
        return false;
    }
    return enable;
}

bool NotificationLiveViewUtils::CheckLiveViewVersion()
{
    int32_t ccmVersion = 0;
    if (LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->GetLiveViewConfigVersion(ccmVersion) != ERR_OK) {
        ANS_LOGW("Live view util get ccm failed");
        return false;
    }

    int32_t version = 0;
    if (NotificationPreferences::GetInstance()->GetLiveViewConfigVersion(version) != ERR_OK) {
        ANS_LOGW("Live view util get db failed");
        return false;
    }

    if (version == 0 || version < ccmVersion) {
        NotificationPreferences::GetInstance()->SetLiveViewConfigVersion(ccmVersion);
        return true;
    }
    return false;
}

void NotificationLiveViewUtils::NotifyLiveViewEvent(const std::string& event)
{
    ANS_LOGI("notify event %{public}s", event.c_str());
    if (CheckLiveViewVersion()) {
        LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->NotifyLiveViewEvent(event, nullptr);
    }
}

void NotificationLiveViewUtils::NotifyLiveViewEvent(const std::string& event,
    const sptr<NotificationBundleOption>& bundleInfo)
{
    ANS_LOGI("notify event %{public}s", event.c_str());
    LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->NotifyLiveViewEvent(event, bundleInfo);
}

bool NotificationLiveViewUtils::CheckLiveViewRebuild(int32_t userId)
{
    std::lock_guard<ffrt::mutex> lock(eraseMutex);
    if (eraseFlag.find(userId) == eraseFlag.end()) {
        eraseFlag[userId] = ERASE_FLAG_INIT;
    } else {
        if (eraseFlag[userId] == ERASE_FLAG_RUNNING || eraseFlag[userId] == ERASE_FLAG_FINISHED) {
            return false;
        }
    }

    std::string rebuildFlag;
    if (NotificationPreferences::GetInstance()->GetLiveViewRebuildFlag(rebuildFlag, userId) != ERR_OK) {
        ANS_LOGW("Live view util get db failed");
        eraseFlag[userId] = ERASE_FLAG_INIT;
        return false;
    }

    if (rebuildFlag.empty()) {
        eraseFlag[userId] = ERASE_FLAG_RUNNING;
        ANS_LOGI("Live view start config.");
        return true;
    }
    eraseFlag[userId] = ERASE_FLAG_FINISHED;
    return false;
}

void NotificationLiveViewUtils::SetLiveViewRebuild(int32_t userId, int32_t data)
{
    std::lock_guard<ffrt::mutex> lock(eraseMutex);
    if (data == ERASE_FLAG_INIT || data == ERASE_FLAG_FINISHED) {
        eraseFlag[userId] = data;
    }
    if (data == ERASE_FLAG_FINISHED) {
        NotificationPreferences::GetInstance()->SetLiveViewRebuildFlag(userId);
    }
}
}
}
