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

#include <functional>
#include <iomanip>
#include <sstream>

#include "accesstoken_kit.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "errors.h"

#include "ipc_skeleton.h"
#include "notification_constant.h"
#include "os_account_manager_helper.h"
#include "hitrace_meter_adapter.h"
#ifdef DISTRIBUTED_NOTIFICATION_SUPPORTED
#include "distributed_notification_manager.h"
#include "distributed_preferences.h"
#include "distributed_screen_status_manager.h"
#endif

#include "advanced_notification_inline.cpp"

namespace OHOS {
namespace Notification {

ErrCode AdvancedNotificationService::Subscribe(
    const sptr<AnsSubscriberInterface> &subscriber, const sptr<NotificationSubscribeInfo> &info)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    ErrCode errCode = ERR_OK;
    do {
        if (subscriber == nullptr) {
            errCode = ERR_ANS_INVALID_PARAM;
            break;
        }

        bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
        if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
            ANS_LOGE("Client is not a system app or subsystem");
            errCode = ERR_ANS_NON_SYSTEM_APP;
            break;
        }

        if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
            errCode = ERR_ANS_PERMISSION_DENIED;
            break;
        }
        
        if (info) {
            errCode = CheckUserIdParams(info->GetAppUserId());
            if (errCode != ERR_OK) {
                break;
            }
        }
        
        errCode = NotificationSubscriberManager::GetInstance()->AddSubscriber(subscriber, info);
        if (errCode != ERR_OK) {
            break;
        }
    } while (0);

    SendSubscribeHiSysEvent(IPCSkeleton::GetCallingPid(), IPCSkeleton::GetCallingUid(), info, errCode);
    return errCode;
}

ErrCode AdvancedNotificationService::SubscribeSelf(const sptr<AnsSubscriberInterface> &subscriber)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);
    sptr<NotificationSubscribeInfo> sptrInfo = new (std::nothrow) NotificationSubscribeInfo();
    ErrCode errCode = ERR_OK;
    do {
        if (subscriber == nullptr) {
            errCode = ERR_ANS_INVALID_PARAM;
            break;
        }

        bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
        if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
            ANS_LOGE("Client is not a system app or subsystem");
            errCode = ERR_ANS_NON_SYSTEM_APP;
            break;
        }

        int32_t uid = IPCSkeleton().GetCallingUid();
        // subscribeSelf doesn't need OHOS_PERMISSION_NOTIFICATION_CONTROLLER permission
        std::string bundle;
        std::shared_ptr<BundleManagerHelper> bundleManager = BundleManagerHelper::GetInstance();
        if (bundleManager != nullptr) {
            bundle = bundleManager->GetBundleNameByUid(uid);
        }

        sptrInfo->AddAppName(bundle);
        sptrInfo->SetSubscriberUid(uid);

        errCode = NotificationSubscriberManager::GetInstance()->AddSubscriber(subscriber, sptrInfo);
        if (errCode != ERR_OK) {
            break;
        }
    } while (0);

    if (errCode == ERR_OK) {
        LivePublishProcess::GetInstance()->AddLiveViewSubscriber();
    }
    SendSubscribeHiSysEvent(IPCSkeleton::GetCallingPid(), IPCSkeleton::GetCallingUid(), sptrInfo, errCode);
    return errCode;
}

ErrCode AdvancedNotificationService::Unsubscribe(
    const sptr<AnsSubscriberInterface> &subscriber, const sptr<NotificationSubscribeInfo> &info)
{
    HITRACE_METER_NAME(HITRACE_TAG_NOTIFICATION, __PRETTY_FUNCTION__);
    ANS_LOGD("%{public}s", __FUNCTION__);

    SendUnSubscribeHiSysEvent(IPCSkeleton::GetCallingPid(), IPCSkeleton::GetCallingUid(), info);

    bool isSubsystem = AccessTokenHelper::VerifyNativeToken(IPCSkeleton::GetCallingTokenID());
    if (!isSubsystem && !AccessTokenHelper::IsSystemApp()) {
        ANS_LOGE("Client is not a system app or subsystem");
        return ERR_ANS_NON_SYSTEM_APP;
    }

    if (!CheckPermission(OHOS_PERMISSION_NOTIFICATION_CONTROLLER)) {
        return ERR_ANS_PERMISSION_DENIED;
    }

    if (subscriber == nullptr) {
        return ERR_ANS_INVALID_PARAM;
    }

    ErrCode errCode = NotificationSubscriberManager::GetInstance()->RemoveSubscriber(subscriber, info);
    if (errCode != ERR_OK) {
        return errCode;
    }

    return ERR_OK;
}
}  // namespace Notification
}  // namespace OHOS
