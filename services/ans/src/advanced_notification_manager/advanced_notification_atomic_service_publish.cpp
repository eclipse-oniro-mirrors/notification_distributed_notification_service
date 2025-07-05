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
 
#include "advanced_notification_service.h"
 
#include "accesstoken_kit.h"
#include "access_token_helper.h"
#include "advanced_notification_flow_control_service.h"
#include "advanced_notification_inline.h"
#include "ans_const_define.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "ans_status.h"
 
#include "hitrace_meter_adapter.h"
#include "notification_analytics_util.h"
#include "os_account_manager.h"
#include "os_account_manager_helper.h"
#include "string_wrapper.h"
#include "hitrace_util.h"

namespace OHOS {
namespace Notification {

ErrCode AdvancedNotificationService::AtomicServicePublish(const sptr<NotificationRequest> &request)
{
    ErrCode result = PermissionVerification();
    if (result != ERR_OK) {
        return result;
    }

    AnsStatus ansStatus = ExecutePublishProcess(request, true);
    if (!ansStatus.Ok()) {
        ansStatus.AppendSceneBranch(EventSceneId::SCENE_1, EventBranchId::BRANCH_0, "Execute PublishProcess failed");
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, ansStatus.BuildMessage(true));
        return ansStatus.GetErrCode();
    }

    sptr<NotificationBundleOption> bundleOption;
    ansStatus = CheckAndPrepareNotificationInfoWithAtomicService(request, bundleOption);
    if (!ansStatus.Ok()) {
        ansStatus.AppendSceneBranch(EventSceneId::SCENE_1, EventBranchId::BRANCH_0,
            "CheckAndPrepareNotificationInfoWithAtomicService failed");
        NotificationAnalyticsUtil::ReportPublishFailedEvent(request, ansStatus.BuildMessage(true));
        SendPublishHiSysEvent(request, result);
        return ansStatus.GetErrCode();
    }

    result = PublishPreparedNotification(request, bundleOption, false);
    if (result != ERR_OK) {
        SendPublishHiSysEvent(request, result);
        return result;
    }
    return result;
}

ErrCode AdvancedNotificationService::SetCreatorInfoWithAtomicService(const sptr<NotificationRequest> &request)
{
    // set agentBundle
    std::string agentBundleName = "";
    if (!AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID())) {
        agentBundleName = GetClientBundleName();
        if (agentBundleName.empty()) {
            ANS_LOGE("Failed to GetClientBundleName");
            return ERR_ANS_INVALID_BUNDLE;
        }
    }

    int32_t uid = IPCSkeleton::GetCallingUid();
    std::shared_ptr<NotificationBundleOption> agentBundle =
        std::make_shared<NotificationBundleOption>(agentBundleName, uid);
    if (agentBundle == nullptr) {
        ANS_LOGE("Failed to create agentBundle instance");
        return ERR_ANS_INVALID_BUNDLE;
    }
    request->SetAgentBundle(agentBundle);
    int32_t pid = IPCSkeleton::GetCallingPid();
    request->SetCreatorUid(uid);
    request->SetCreatorPid(pid);
    int userId = -1;
    OsAccountManagerHelper::GetInstance().GetOsAccountLocalIdFromUid(uid, userId);
    request->SetCreatorUserId(userId);
    request->SetCreatorBundleName(agentBundleName);
    return ERR_OK;
}

AnsStatus AdvancedNotificationService::CheckAndPrepareNotificationInfoWithAtomicService(
    const sptr<NotificationRequest> &request, sptr<NotificationBundleOption> &bundleOption)
{
    ErrCode result = CheckUserIdParams(request->GetReceiverUserId());
    if (result != ERR_OK) {
        return AnsStatus(result, "User is invalid");
    }
    if (request->GetOwnerUserId() <= SUBSCRIBE_USER_INIT || request->GetOwnerBundleName().empty()) {
        return AnsStatus(ERR_ANS_INVALID_PARAM, "OwnerUserId or OwnerBundleName invalid");
    }
    CheckRemovalWantAgent(request);
    request->SetCreateTime(GetCurrentTime());
    if (request->GetDeliveryTime() <= 0) {
        request->SetDeliveryTime(GetCurrentTime());
    }
    result = CheckPictureSize(request);

    SetCreatorInfoWithAtomicService(request);
    request->SetOwnerUid(0);

    FillActionButtons(request);

    bundleOption = new (std::nothrow) NotificationBundleOption(request->GetOwnerBundleName(),
        request->GetOwnerUid());
    if (bundleOption == nullptr) {
        return AnsStatus(ERR_ANS_INVALID_BUNDLE, "create bundleOption failed");
    }
    SetClassificationWithVoip(request);
    request->SetNotDistributed(false);
    SetRequestBySlotType(request, bundleOption);

    result = CheckSoundPermission(request, bundleOption->GetBundleName());
    if (result != ERR_OK) {
        return AnsStatus(result, "CheckSoundPermission failed");
    }
    if (IsNeedPushCheck(request)) {
        result = PushCheck(request);
        if (result != ERR_OK) {
            return AnsStatus(result, "PushCheck failed");
        }
    }
    return AnsStatus();
}

AnsStatus AdvancedNotificationService::ExecutePublishProcess(
    const sptr<NotificationRequest> &request, bool isUpdateByOwnerAllowed)
{
    if (!InitPublishProcess()) {
        return AnsStatus(ERR_ANS_NO_MEMORY, "InitPublishProcess failed");
    }

    AnsStatus ansStatus = publishProcess_[request->GetSlotType()]->PublishPreWork(request, isUpdateByOwnerAllowed);
    if (!ansStatus.Ok()) {
        return ansStatus;
    }

    ErrCode result = publishProcess_[request->GetSlotType()]->PublishNotificationByApp(request);
    if (result != ERR_OK) {
        return AnsStatus(result, "PublishNotificationByApp failed");
    }
    return AnsStatus();
}

}
}