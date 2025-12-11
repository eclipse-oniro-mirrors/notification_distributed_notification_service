/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "ans_log_wrapper.h"
#include "bundle_manager_helper.h"
#include "extension_service_connection_service.h"
#include "extension_service_subscriber.h"
#include "os_account_manager.h"
#include "parameters.h"

namespace OHOS {
namespace Notification {
namespace {
    const char* IS_PCMODE_PARAM_NAME = "persist.sceneboard.ispcmode";
    const char* IS_PCMODE_PARAM_DEFALT_VALUE = "false";
}

bool ExtensionServiceSubscriber::Init(const sptr<NotificationBundleOption> &bundle)
{
    if (messageQueue_ != nullptr) {
        return true;
    }
    messageQueue_ = std::make_shared<ffrt::queue>("extension service subscriber");
    if (messageQueue_ == nullptr) {
        ANS_LOGW("ffrt create failed!");
        return false;
    }

    int32_t bundleUserId = -1;
    auto result = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(bundle->GetUid(), bundleUserId);
    if (result != ERR_OK) {
        ANS_LOGE("Failed to GetOsAccountLocalIdFromUid for bundle, uid: %{public}d, ret: %{public}d",
            bundle->GetUid(), result);
        return false;
    }
    auto flags = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION)
        | static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE)
        | static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY);
    std::string bundleName = bundle->GetBundleName();
    AppExecFwk::BundleInfo bundleInfo;
    if (!BundleManagerHelper::GetInstance()->GetBundleInfoV9(bundleName, flags, bundleInfo, bundleUserId)) {
        ANS_LOGE("GetBundleInfoV9 error, bundleName = %{public}s, userId = %{public}d",
            bundleName.c_str(), bundleUserId);
        return false;
    }
    for (const auto& hapmodule : bundleInfo.hapModuleInfos) {
        for (const auto& extInfo : hapmodule.extensionInfos) {
            if (extInfo.type == AppExecFwk::ExtensionAbilityType::NOTIFICATION_SUBSCRIBER) {
                auto info = std::make_shared<ExtensionSubscriberInfo>();
                info->bundleName = bundleName;
                info->extensionName = extInfo.name;
                info->uid = bundle->GetUid();
                info->userId = bundleUserId;
                extensionSubscriberInfo_ = info;
                return true;
            }
        }
    }
    return false;
}

ExtensionServiceSubscriber::~ExtensionServiceSubscriber()
{
    if (messageQueue_ == nullptr) {
        return;
    }
    ffrt::task_handle handler = messageQueue_->submit_h([this]() {
        if (extensionSubscriberInfo_ == nullptr) {
            ANS_LOGE("null extension subsciber info");
            return;
        }
        ExtensionServiceConnectionService::GetInstance().CloseConnection(*extensionSubscriberInfo_);
    });
    messageQueue_->wait(handler);
}

void ExtensionServiceSubscriber::OnDied()
{
    ANS_LOGD("ExtensionServiceSubscriber::OnDied");
}

void ExtensionServiceSubscriber::OnConnected()
{
    ANS_LOGD("ExtensionServiceSubscriber::OnConnected");
}

void ExtensionServiceSubscriber::OnDisconnected()
{
    ANS_LOGD("ExtensionServiceSubscriber::OnDisconnected");
}

void ExtensionServiceSubscriber::OnCanceled(const std::shared_ptr<Notification> &request,
    const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason)
{
    ANS_LOGD("ExtensionServiceSubscriber::OnCanceled");
    if (messageQueue_ == nullptr) {
        ANS_LOGE("null queue");
        return;
    }

    messageQueue_->submit([request, this]() {
        std::string isPCMode = OHOS::system::GetParameter(IS_PCMODE_PARAM_NAME, IS_PCMODE_PARAM_DEFALT_VALUE);
        if (isPCMode == "true") {
            ANS_LOGW("PC Mode, skip NotifyOnReceiveMessage");
            return;
        }
        if (request == nullptr) {
            ANS_LOGE("null request");
            return;
        }
        auto requestPoint = request->GetNotificationRequestPoint();
        if (requestPoint == nullptr) {
            ANS_LOGE("null requestPoint");
            return;
        }
        auto hashCodes = std::make_shared<std::vector<std::string>>();
        if (hashCodes == nullptr) {
            ANS_LOGE("null hashCodes");
            return;
        }
        hashCodes->emplace_back(requestPoint->GetBaseKey(""));
        if (extensionSubscriberInfo_ == nullptr) {
            ANS_LOGE("null extension subsciber info");
            return;
        }
        ExtensionServiceConnectionService::GetInstance().NotifyOnCancelMessages(
            extensionSubscriberInfo_, hashCodes);
    });
}

void ExtensionServiceSubscriber::OnConsumed(const std::shared_ptr<Notification> &request,
    const std::shared_ptr<NotificationSortingMap> &sortingMap)
{
    ANS_LOGD("ExtensionServiceSubscriber::OnConsumed");
    if (messageQueue_ == nullptr) {
        ANS_LOGE("null queue");
        return;
    }

    messageQueue_->submit([request, this]() {
        std::string isPCMode = OHOS::system::GetParameter(IS_PCMODE_PARAM_NAME, IS_PCMODE_PARAM_DEFALT_VALUE);
        if (isPCMode == "true") {
            ANS_LOGW("PC Mode, skip NotifyOnReceiveMessage");
            return;
        }
        if (request == nullptr) {
            ANS_LOGE("null request");
            return;
        }
        auto requestPoint = request->GetNotificationRequestPoint();
        if (requestPoint == nullptr) {
            ANS_LOGE("null requestPoint");
            return;
        }
        if (extensionSubscriberInfo_ == nullptr) {
            ANS_LOGE("null extension subsciber info");
            return;
        }
        ExtensionServiceConnectionService::GetInstance().NotifyOnReceiveMessage(
            extensionSubscriberInfo_, requestPoint);
    });
}

void ExtensionServiceSubscriber::OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap)
{
    ANS_LOGD("ExtensionServiceSubscriber::OnUpdate");
}

void ExtensionServiceSubscriber::OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("ExtensionServiceSubscriber::OnDoNotDisturbDateChange");
}

void ExtensionServiceSubscriber::OnEnabledNotificationChanged(
    const std::shared_ptr<EnabledNotificationCallbackData> &callbackData)
{
    ANS_LOGD("ExtensionServiceSubscriber::OnEnabledNotificationChanged");
}

void ExtensionServiceSubscriber::OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData)
{
    ANS_LOGD("ExtensionServiceSubscriber::OnBadgeChanged");
}

void ExtensionServiceSubscriber::OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData)
{
    ANS_LOGD("ExtensionServiceSubscriber::OnBadgeEnabledChanged");
}

void ExtensionServiceSubscriber::OnBatchCanceled(const std::vector<std::shared_ptr<Notification>> &requestList,
    const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason)
{
    ANS_LOGD("ExtensionServiceSubscriber::OnDied");
}

ErrCode ExtensionServiceSubscriber::OnOperationResponse(const std::shared_ptr<NotificationOperationInfo> &operationInfo)
{
    ANS_LOGD("ExtensionServiceSubscriber::OnOperationResponse");
    return ERR_OK;
}

void ExtensionServiceSubscriber::OnApplicationInfoNeedChanged(const std::string& bundleName)
{
    ANS_LOGD("ExtensionServiceSubscriber::OnApplicationInfoNeedChanged");
}
}
}
