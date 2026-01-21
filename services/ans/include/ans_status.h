/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_ANS_STATUS_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_ANS_STATUS_H

#include <string>
#include <cstdint>
#include <climits>
#include "notification_analytics_util.h"

namespace OHOS {
namespace Notification {
class AnsStatus {
public:
    AnsStatus() = default;
    AnsStatus(int32_t errCode, const std::string& msg);
    AnsStatus(int32_t errCode, const std::string& msg, int32_t sceneId, int32_t branchId);
    bool Ok();
    bool hasPoint();
    AnsStatus& AppendSceneBranch(int32_t sceneId, int32_t branchId);
    AnsStatus& AppendSceneBranch(int32_t sceneId, int32_t branchId, const std::string& msg);
    int32_t GetErrCode();
    std::string GetMsg();
    
    static AnsStatus InvalidParam(int32_t sceneId, int32_t branchId);
    static AnsStatus InvalidParam(const std::string& msg, int32_t sceneId, int32_t branchId);

    static AnsStatus NoMemory(int32_t sceneId, int32_t branchId);
    static AnsStatus NoMemory(const std::string& msg, int32_t sceneId, int32_t branchId);
 
    static AnsStatus InvalidBundle(int32_t sceneId, int32_t branchId);
    static AnsStatus InvalidBundle(const std::string& msg, int32_t sceneId, int32_t branchId);
 
    static AnsStatus InvalidUid(int32_t sceneId, int32_t branchId);
    static AnsStatus InvalidUid(const std::string& msg, int32_t sceneId, int32_t branchId);
 
    static AnsStatus NonSystemApp(int32_t sceneId, int32_t branchId);
    static AnsStatus NonSystemApp(const std::string& msg, int32_t sceneId, int32_t branchId);
 
    static AnsStatus PermissionDeny(int32_t sceneId, int32_t branchId);
    static AnsStatus PermissionDeny(const std::string& msg, int32_t sceneId, int32_t branchId);

    HaMetaMessage BuildMessage(bool isPrint);
private:
    std::string FormatSceneBranchStr(int32_t sceneId, int32_t branchId);
    int32_t errCode_{0};
    std::string msg_{};
    int32_t branchId_{INT32_MAX};
    int32_t sceneId_{INT32_MAX};
    std::string path_{};
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_SERVICES_ANS_INCLUDE_ANS_STATUS_H
