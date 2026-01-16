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
#include "ans_status.h"
#include <string>
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"

namespace OHOS {
namespace Notification {

AnsStatus::AnsStatus(int32_t errCode, const std::string& msg)
{
    errCode_ = errCode;
    msg_ = msg;
}

AnsStatus::AnsStatus(int32_t errCode, const std::string& msg, int32_t sceneId, int32_t branchId)
{
    errCode_ = errCode;
    msg_ = msg;
    sceneId_ = sceneId;
    branchId_ = branchId;
    path_ = FormatSceneBranchStr(sceneId, branchId);
}

bool AnsStatus::Ok()
{
    return errCode_ == ERR_OK;
}

std::string AnsStatus::FormatSceneBranchStr(int32_t sceneId, int32_t branchId)
{
    return std::to_string(sceneId) + "_" + std::to_string(branchId);
}

AnsStatus& AnsStatus::AppendSceneBranch(int32_t sceneId, int32_t branchId)
{
    if (sceneId == -1 && branchId == -1) {
        return *this;
    }
    return AppendSceneBranch(sceneId, branchId, "");
}

AnsStatus& AnsStatus::AppendSceneBranch(int32_t sceneId, int32_t branchId, const std::string& msg)
{
    std::string path = FormatSceneBranchStr(sceneId, branchId);
    path_.append("#" + path);
    msg_.append("#" + msg);
    return *this;
}

int32_t AnsStatus::GetErrCode()
{
    return errCode_;
}

AnsStatus AnsStatus::InvalidParam(int32_t sceneId, int32_t branchId)
{
    return AnsStatus::InvalidParam("Invalid param", sceneId, branchId);
}

AnsStatus AnsStatus::InvalidParam(const std::string& msg, int32_t sceneId, int32_t branchId)
{
    return AnsStatus(ERR_ANS_INVALID_PARAM, msg, sceneId, branchId);
}

AnsStatus AnsStatus::NoMemory(int32_t sceneId, int32_t branchId)
{
    return AnsStatus::NoMemory("No memory", sceneId, branchId);
}
 
AnsStatus AnsStatus::NoMemory(const std::string& msg, int32_t sceneId, int32_t branchId)
{
    return AnsStatus(ERR_ANS_NO_MEMORY, msg, sceneId, branchId);
}
 
AnsStatus AnsStatus::InvalidBundle(int32_t sceneId, int32_t branchId)
{
    return AnsStatus::InvalidBundle("invalid bundle", sceneId, branchId);
}
 
AnsStatus AnsStatus::InvalidBundle(const std::string& msg, int32_t sceneId, int32_t branchId)
{
    return AnsStatus(ERR_ANS_INVALID_BUNDLE, msg, sceneId, branchId);
}
 
AnsStatus AnsStatus::InvalidUid(int32_t sceneId, int32_t branchId)
{
    return AnsStatus::InvalidUid("invalid uid", sceneId, branchId);
}
 
AnsStatus AnsStatus::InvalidUid(const std::string& msg, int32_t sceneId, int32_t branchId)
{
    return AnsStatus(ERR_ANS_INVALID_UID, msg, sceneId, branchId);
}
 
AnsStatus AnsStatus::NonSystemApp(int32_t sceneId, int32_t branchId)
{
    return AnsStatus::NonSystemApp("not system app", sceneId, branchId);
}
 
AnsStatus AnsStatus::NonSystemApp(const std::string& msg, int32_t sceneId, int32_t branchId)
{
    return AnsStatus(ERR_ANS_NON_SYSTEM_APP, msg, sceneId, branchId);
}
 
AnsStatus AnsStatus::PermissionDeny(int32_t sceneId, int32_t branchId)
{
    return AnsStatus::PermissionDeny("permission denied", sceneId, branchId);
}
 
AnsStatus AnsStatus::PermissionDeny(const std::string& msg, int32_t sceneId, int32_t branchId)
{
    return AnsStatus(ERR_ANS_PERMISSION_DENIED, msg, sceneId, branchId);
}

HaMetaMessage AnsStatus::BuildMessage(bool isPrint)
{
    return HaMetaMessage(sceneId_, branchId_).Path(path_)
        .ErrorCode(errCode_).Message(msg_, isPrint);
}

}  // namespace Notification
}  // namespace OHOS
