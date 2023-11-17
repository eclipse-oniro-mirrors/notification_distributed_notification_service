/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_CHECK_INFO_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_CHECK_INFO_H

#include "nlohmann/json.hpp"
#include "want.h"

namespace OHOS {
namespace Notification {

class NotificationCheckInfo {
private:
    std::string pkgName_;
    int32_t notifyId_;
    int32_t contentType_;
    int32_t creatorUserId_;
    int32_t slotType_;
    std::string label_;
    std::shared_ptr<AAFwk::WantParams> extraInfo_ {};
    void ConvertJsonExtraInfoToValue(nlohmann::json &jsonobj);
public:
    NotificationCheckInfo() = default;
    NotificationCheckInfo(std::string pkgName, int32_t notifyId, int32_t contentType,
    int32_t creatorUserId, int32_t slotType, std::shared_ptr<AAFwk::WantParams> extraInfo);
    ~NotificationCheckInfo();
    std::string GetPkgName() const;
    void SetPkgName(std::string pkgName);
    int32_t GetNotifyId() const;
    void SetNotifyId(int32_t notifyId);
    int32_t GetContentType() const;
    void SetContentType(int32_t contentType);
    int32_t GetCreatorUserId() const;
    void SetCreatorUserId(int32_t creatorUserId);
    int32_t GetSlotType() const;
    void SetSlotType(int32_t slotType);
    std::string GetLabel() const;
    void SetLabel(std::string label);
    std::shared_ptr<AAFwk::WantParams> GetExtraInfo() const;
    void SetExtraInfo(std::shared_ptr<AAFwk::WantParams> extraInfo);
    void ConvertJsonStringToValue(const std::string &notificationData);
};
}  // namespace Notification
}  // namespace OHOS

#endif  //BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_INTERFACES_INNER_API_NOTIFICATION_CHECK_INFO_H
