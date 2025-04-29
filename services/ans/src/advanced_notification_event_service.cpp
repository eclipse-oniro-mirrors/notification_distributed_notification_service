/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "advanced_notification_service.h"

#include <cstdint>
#include <functional>
#include <iomanip>
#include <sstream>

#include "access_token_helper.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_permission_def.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "event_report.h"
#include "errors.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "hitrace_meter_adapter.h"
#include "ipc_skeleton.h"

#include "advanced_notification_inline.cpp"

namespace OHOS {
namespace Notification {
void AdvancedNotificationService::SendSubscribeHiSysEvent(int32_t pid, int32_t uid,
    const sptr<NotificationSubscribeInfo> &info, ErrCode errCode)
{
    EventInfo eventInfo;
    eventInfo.pid = pid;
    eventInfo.uid = uid;
    if (info != nullptr) {
        ANS_LOGD("info is not nullptr.");
        eventInfo.userId = info->GetAppUserId();
        std::vector<std::string> appNames = info->GetAppNames();
        eventInfo.bundleName = std::accumulate(appNames.begin(), appNames.end(), std::string(""),
            [appNames](const std::string &bundleName, const std::string &str) {
                return (str == appNames.front()) ? (bundleName + str) : (bundleName + "," + str);
            });
    }

    if (errCode != ERR_OK) {
        eventInfo.errCode = errCode;
        EventReport::SendHiSysEvent(SUBSCRIBE_ERROR, eventInfo);
    } else {
        EventReport::SendHiSysEvent(SUBSCRIBE, eventInfo);
    }
}

void AdvancedNotificationService::SendUnSubscribeHiSysEvent(int32_t pid, int32_t uid,
    const sptr<NotificationSubscribeInfo> &info)
{
    EventInfo eventInfo;
    eventInfo.pid = pid;
    eventInfo.uid = uid;
    if (info != nullptr) {
        eventInfo.userId = info->GetAppUserId();
        std::vector<std::string> appNames = info->GetAppNames();
        eventInfo.bundleName = std::accumulate(appNames.begin(), appNames.end(), std::string(""),
            [appNames](const std::string &bundleName, const std::string &str) {
                return (str == appNames.front()) ? (bundleName + str) : (bundleName + "," + str);
            });
    }

    EventReport::SendHiSysEvent(UNSUBSCRIBE, eventInfo);
}

void AdvancedNotificationService::SendPublishHiSysEvent(const sptr<NotificationRequest> &request, ErrCode errCode)
{
    if (request == nullptr) {
        return;
    }

    EventInfo eventInfo;
    eventInfo.notificationId = request->GetNotificationId();
    eventInfo.contentType = static_cast<int32_t>(request->GetNotificationType());
    eventInfo.bundleName = request->GetCreatorBundleName();
    eventInfo.userId = request->GetCreatorUserId();
    eventInfo.slotType = request->GetSlotType();
    eventInfo.classification = request->GetClassification();
    if (request->GetFlags() != nullptr) {
        eventInfo.reminderFlags = request->GetFlags()->GetReminderFlags();
    }
    eventInfo.notificationControlFlags = request->GetNotificationControlFlags();
    if (errCode != ERR_OK) {
        eventInfo.errCode = errCode;
        EventReport::SendHiSysEvent(PUBLISH_ERROR, eventInfo);
    } else {
        EventReport::SendHiSysEvent(PUBLISH, eventInfo);
    }
}

void AdvancedNotificationService::SendCancelHiSysEvent(int32_t notificationId, const std::string &label,
    const sptr<NotificationBundleOption> &bundleOption, ErrCode errCode)
{
    if (bundleOption == nullptr || errCode != ERR_OK) {
        ANS_LOGD("bundleOption is nullptr or not ok %{public}d.", errCode);
        return;
    }

    EventInfo eventInfo;
    eventInfo.notificationId = notificationId;
    eventInfo.notificationLabel = label;
    eventInfo.bundleName = bundleOption->GetBundleName();
    eventInfo.uid = bundleOption->GetUid();
    EventReport::SendHiSysEvent(CANCEL, eventInfo);
}

void AdvancedNotificationService::SendRemoveHiSysEvent(int32_t notificationId, const std::string &label,
    const sptr<NotificationBundleOption> &bundleOption, ErrCode errCode)
{
    if (bundleOption == nullptr || errCode != ERR_OK) {
        return;
    }

    EventInfo eventInfo;
    eventInfo.notificationId = notificationId;
    eventInfo.notificationLabel = label;
    eventInfo.bundleName = bundleOption->GetBundleName();
    eventInfo.uid = bundleOption->GetUid();
    EventReport::SendHiSysEvent(REMOVE, eventInfo);
}

void AdvancedNotificationService::SendEnableNotificationHiSysEvent(const sptr<NotificationBundleOption> &bundleOption,
    bool enabled, ErrCode errCode)
{
    if (bundleOption == nullptr) {
        return;
    }

    EventInfo eventInfo;
    eventInfo.bundleName = bundleOption->GetBundleName();
    eventInfo.uid = bundleOption->GetUid();
    eventInfo.enable = enabled;
    if (errCode != ERR_OK) {
        eventInfo.errCode = errCode;
        EventReport::SendHiSysEvent(ENABLE_NOTIFICATION_ERROR, eventInfo);
    } else {
        EventReport::SendHiSysEvent(ENABLE_NOTIFICATION, eventInfo);
    }
}

void AdvancedNotificationService::SendEnableNotificationSlotHiSysEvent(
    const sptr<NotificationBundleOption> &bundleOption, const NotificationConstant::SlotType &slotType,
    bool enabled, ErrCode errCode)
{
    if (bundleOption == nullptr) {
        return;
    }

    EventInfo eventInfo;
    eventInfo.bundleName = bundleOption->GetBundleName();
    eventInfo.uid = bundleOption->GetUid();
    eventInfo.slotType = slotType;
    eventInfo.enable = enabled;
    if (errCode != ERR_OK) {
        eventInfo.errCode = errCode;
        EventReport::SendHiSysEvent(ENABLE_NOTIFICATION_SLOT_ERROR, eventInfo);
    } else {
        EventReport::SendHiSysEvent(ENABLE_NOTIFICATION_SLOT, eventInfo);
    }
}

void AdvancedNotificationService::SendFlowControlOccurHiSysEvent(const std::shared_ptr<NotificationRecord> &record)
{
    if (record == nullptr || record->request == nullptr || record->bundleOption == nullptr) {
        return;
    }

    EventInfo eventInfo;
    eventInfo.notificationId = record->request->GetNotificationId();
    eventInfo.bundleName = record->bundleOption->GetBundleName();
    eventInfo.uid = record->bundleOption->GetUid();
    EventReport::SendHiSysEvent(FLOW_CONTROL_OCCUR, eventInfo);
}

void AdvancedNotificationService::SendLiveViewUploadHiSysEvent(
    const std::shared_ptr<NotificationRecord> &record, int32_t uploadStatus)
{
    if (record == nullptr || record->request == nullptr ||
        uploadStatus < UploadStatus::CREATE || uploadStatus > UploadStatus::END) {
        return;
    }

    EventInfo eventInfo;
    eventInfo.notificationId = record->request->GetNotificationId();
    eventInfo.bundleName = record->request->GetCreatorBundleName();
    eventInfo.contentType = static_cast<int32_t>(record->request->GetNotificationType());
    eventInfo.operateFlag = uploadStatus;
    EventReport::SendHiSysEvent(STATIC_LIVE_VIEW_UPLOAD, eventInfo);
}
}  // namespace Notification
}  // namespace OHOS
