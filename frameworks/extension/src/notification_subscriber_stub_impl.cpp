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

#include "ans_log_wrapper.h"
#include "notification_subscriber_stub_impl.h"

namespace OHOS {
namespace Notification {

ErrCode NotificationSubscriberStubImpl::OnReceiveMessage(
    const sptr<NotificationRequest>& notificationRequest, int32_t& retResult)
{
    ANS_LOGD("OnReceiveMessage begin.");
    if (notificationRequest == nullptr) {
        ANS_LOGE("null notificationRequest");
        return ERR_INVALID_DATA;
    }
    auto extension = extension_.lock();
    if (extension == nullptr) {
        ANS_LOGE("null extension");
        return ERR_INVALID_DATA;
    }
    auto param = ConvertNotificationRequest(notificationRequest);
    if (param == nullptr) {
        ANS_LOGE("ConvertNotificationRequest error");
        return ERR_INVALID_DATA;
    }
    retResult = static_cast<int32_t>(extension->OnReceiveMessage(param));
    ANS_LOGI("OnReceiveMessage end successfully.");
    return ERR_OK;
}

ErrCode NotificationSubscriberStubImpl::OnCancelMessages(const std::vector<std::string>& hashCode, int32_t& retResult)
{
    ANS_LOGD("OnCancelMessages begin.");
    auto extension = extension_.lock();
    if (extension != nullptr) {
        std::shared_ptr<std::vector<std::string>> param = std::make_shared<std::vector<std::string>>(hashCode);
        retResult = static_cast<int32_t>(extension->OnCancelMessages(param));
        ANS_LOGI("OnCancelMessages end successfully.");
        return ERR_OK;
    }
    ANS_LOGE("OnCancelMessages end failed.");
    return ERR_INVALID_DATA;
}

std::shared_ptr<NotificationInfo> NotificationSubscriberStubImpl::ConvertNotificationRequest(
    const sptr<NotificationRequest>& notificationRequest)
{
    auto notificationInfo = std::make_shared<NotificationInfo>();
    if (notificationInfo == nullptr) {
        ANS_LOGE("null notificationInfo");
        return nullptr;
    }
    notificationInfo->SetHashCode(notificationRequest->GetBaseKey(""));
    notificationInfo->SetNotificationSlotType(notificationRequest->GetSlotType());
    auto content = notificationRequest->GetContent();
    if (content == nullptr) {
        ANS_LOGE("null content");
        return nullptr;
    }
    auto basicContent = content->GetNotificationContent();
    if (basicContent == nullptr) {
        ANS_LOGE("null basicContent");
        return nullptr;
    }
    auto notificationContent = std::make_shared<NotificationExtensionContent>();
    if (notificationContent == nullptr) {
        ANS_LOGE("null notificationContent");
        return nullptr;
    }
    notificationContent->SetTitle(basicContent->GetTitle());
    notificationContent->SetText(basicContent->GetText());
    notificationInfo->SetNotificationExtensionContent(notificationContent);
    notificationInfo->SetBundleName(notificationRequest->GetOwnerBundleName());
    notificationInfo->SetAppName(notificationRequest->GetAppName());
    notificationInfo->SetDeliveryTime(notificationRequest->GetDeliveryTime());
    notificationInfo->SetGroupName(notificationRequest->GetGroupName());
    notificationInfo->SetAppIndex(notificationRequest->GetAppIndex());
    return notificationInfo;
}
} // namespace EventFwk
} // namespace OHOS
