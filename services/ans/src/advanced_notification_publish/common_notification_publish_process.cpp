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

#include "common_notification_publish_process.h"

#include "access_token_helper.h"
#include "advanced_notification_inline.h"
#include "ans_const_define.h"
#include "ans_log_wrapper.h"
#include "bool_wrapper.h"
#include "notification_analytics_util.h"
#include "parameters.h"
#include "want_params.h"

namespace OHOS {
namespace Notification {
namespace {
bool IsWearableDevice()
{
    // const.product.devicetype is a boot-time constant; cache it once per process
    // to avoid reading the system parameter on every publish request.
    static bool isWearable = OHOS::system::GetParameter("const.product.devicetype", "") == "wearable";
    return isWearable;
}
}

std::shared_ptr<CommonNotificationPublishProcess> CommonNotificationPublishProcess::instance_;
ffrt::mutex CommonNotificationPublishProcess::instanceMutex_;

std::shared_ptr<CommonNotificationPublishProcess> CommonNotificationPublishProcess::GetInstance()
{
    std::lock_guard<ffrt::mutex> lock(instanceMutex_);

    if (instance_ == nullptr) {
        instance_ = std::make_shared<CommonNotificationPublishProcess>();
        if (instance_ == nullptr) {
            ANS_LOGE("null instance");
            return nullptr;
        }
    }
    return instance_;
}

AnsStatus CommonNotificationPublishProcess::PublishNotificationByApp(const sptr<NotificationRequest> &request)
{
    AnsStatus ansStatus = CommonPublishCheck(request);
    if (!ansStatus.Ok()) {
        return ansStatus;
    }

    if (request->IsInProgress()) {
        if (!AccessTokenHelper::IsSystemApp()) {
            request->SetInProgress(false);
        } else if (!IsWearableDevice()) {
            // Non-wearable devices: system app inProgress is degraded to false.
            std::string bundleName = GetClientBundleName();
            HaMetaMessage message = HaMetaMessage(EventSceneId::SCENE_36, EventBranchId::BRANCH_0)
                .SlotType(static_cast<int32_t>(request->GetSlotType()))
                .Message("sysApp inProgress, bn:" + bundleName +
                    ", ct:" + std::to_string(static_cast<int32_t>(request->GetNotificationType())) +
                    ", id:" + std::to_string(request->GetNotificationId()));
            NotificationAnalyticsUtil::ReportModifyEvent(message);
            // Record the degradation so wearable subscribers can recover inProgress later.
            auto extendInfo = request->GetExtendInfo();
            if (extendInfo == nullptr) {
                request->SetExtendInfo(std::make_shared<AAFwk::WantParams>());
                extendInfo = request->GetExtendInfo();
            }
            if (extendInfo != nullptr) {
                extendInfo->SetParam(EXTENDINFO_RECOVER_INPROGRESS, AAFwk::Boolean::Box(true));
            }
            request->SetInProgress(false);
        }
        // Wearable devices: system app inProgress keeps true, no event reported.
    }

    ansStatus = CommonPublishProcess(request);
    if (!ansStatus.Ok()) {
        return ansStatus;
    }
    return AnsStatus();
}
}  // namespace Notification
}  // namespace OHOS
