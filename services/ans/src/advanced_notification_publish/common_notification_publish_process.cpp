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
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {
std::shared_ptr<CommonNotificationPublishProcess> CommonNotificationPublishProcess::instance_;
std::mutex CommonNotificationPublishProcess::instanceMutex_;

std::shared_ptr<CommonNotificationPublishProcess> CommonNotificationPublishProcess::GetInstance()
{
    std::lock_guard<std::mutex> lock(instanceMutex_);

    if (instance_ == nullptr) {
        instance_ = std::make_shared<CommonNotificationPublishProcess>();
        if (instance_ == nullptr) {
            ANS_LOGE("null instance");
            return nullptr;
        }
    }
    return instance_;
}

ErrCode CommonNotificationPublishProcess::PublishNotificationByApp(const sptr<NotificationRequest> &request)
{
    ErrCode result = CommonPublishCheck(request);
    if (result != ERR_OK) {
        return result;
    }

    if (request->IsInProgress() &&
        !AccessTokenHelper::IsSystemApp()) {
        request->SetInProgress(false);
    }

    result = CommonPublishProcess(request);
    if (result != ERR_OK) {
        return result;
    }
    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS
