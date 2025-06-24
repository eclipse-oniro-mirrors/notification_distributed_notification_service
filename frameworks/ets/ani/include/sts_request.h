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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_REQUEST_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_REQUEST_H
#include "ani.h"
#include "notification.h"
#include "notification_request.h"

namespace OHOS {
namespace NotificationSts {
using namespace OHOS::Notification;
using NotificationSts = OHOS::Notification::Notification;

struct StsDistributedOptions {
    bool isDistributed = false;
    std::vector<std::string> supportDisplayDevices = {};
    std::vector<std::string> supportOperateDevices = {};
    int32_t remindType = -1;
};

void UnWarpDistributedOptions(ani_env *env, ani_object obj, StsDistributedOptions distributedOptions);
bool WarpNotificationUnifiedGroupInfo(ani_env* env,
    const std::shared_ptr<NotificationUnifiedGroupInfo> &groupInfo, ani_object &groupInfoObject);

ani_status UnWarpNotificationRequest(
    ani_env *env, ani_object obj, std::shared_ptr<NotificationRequest> &notificationRequest);
bool WarpNotificationRequest(
    ani_env *env, const NotificationRequest *notificationRequest, ani_class &cls, ani_object &outAniObj);
ani_object GetAniNotificationRequestArray(ani_env *env, std::vector<sptr<NotificationRequest>> requests);
ani_object GetAniNotificationRequestArrayByNotifocations(ani_env *env, std::vector<sptr<NotificationSts>> requests);

bool UnWarpNotificationCheckRequest(ani_env *env, ani_object obj, sptr<NotificationCheckRequest> &checkRequest);
bool UnWarpNotificationFilter(ani_env *env, ani_object obj, LiveViewFilter& filter);
} // namespace NotificationSts
} // OHOS
#endif