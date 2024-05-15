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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_BASE_PUBLISH_PROCESS_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_BASE_PUBLISH_PROCESS_H

#include "notification_request.h"

namespace OHOS {
namespace Notification {
class BasePublishProcess {
public:
    BasePublishProcess();
    ~BasePublishProcess() = default;
    virtual ErrCode PublishPreWork(const sptr<NotificationRequest> &request, bool isUpdateByOwnerAllowed);
    virtual ErrCode PublishNotificationByApp(const sptr<NotificationRequest> &request) = 0;
    bool CheckPermission(const std::string &permission);
    ErrCode CommonPublishCheck(const sptr<NotificationRequest> &request);
    ErrCode CommonPublishProcess(const sptr<NotificationRequest> &request);

private:
    static std::string supportCheckSaPermission_;
};
}  // namespace Notification
}  // namespace OHOS

#endif // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_BASE_PUBLISH_PROCESS_H
