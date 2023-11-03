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

#include "notification_dialog_manager.h"

#include "common_event_manager.h"
#include "matching_skills.h"

#include "advanced_notification_service.h"
#include "ans_const_define.h"
#include "ans_log_wrapper.h"
#include "notification_bundle_option.h"
#include "notification_dialog.h"
#include "notification_preferences.h"

namespace OHOS::Notification {
using DialogInfo = NotificationDialogManager::DialogInfo;

std::shared_ptr<NotificationDialogEventSubscriber> NotificationDialogEventSubscriber::Create(
    NotificationDialogManager& dialogManager)
{
    ANS_LOGD("enter");
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(NotificationDialogEventSubscriber::EVENT_NAME);
    EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    subscriberInfo.SetPublisherBundleName(NotificationDialogManager::NOTIFICATION_DIALOG_SERVICE_BUNDLE);
    return std::make_shared<NotificationDialogEventSubscriber>(dialogManager, subscriberInfo);
}

NotificationDialogEventSubscriber::NotificationDialogEventSubscriber(
    NotificationDialogManager& dialogManager, const EventFwk::CommonEventSubscribeInfo& subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo), dialogManager_(dialogManager)
{ }

void NotificationDialogEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData& data)
{
    int32_t code = data.GetCode();
    std::string text = data.GetData();
    ANS_LOGI("NotificationDialogEventSubscriber Get Data %{public}d %{public}s", code, text.c_str());
    dialogManager_.OnBundleEnabledStatusChanged(
        static_cast<DialogStatus>(code), text);
}

NotificationDialogEventSubscriber::~NotificationDialogEventSubscriber()
{
    ANS_LOGD("enter");
}

NotificationDialogManager::NotificationDialogManager(AdvancedNotificationService& ans)
    : ans_(ans)
{
    ANS_LOGD("enter");
}

NotificationDialogManager::~NotificationDialogManager()
{
    ANS_LOGD("enter");
}

bool NotificationDialogManager::Init()
{
    ANS_LOGD("enter");

    dialogEventSubscriber = NotificationDialogEventSubscriber::Create(*this);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(dialogEventSubscriber)) {
        ANS_LOGE("SubscribeCommonEvent Failed.");
        dialogEventSubscriber = nullptr;
        return false;
    }
    return true;
}

ErrCode NotificationDialogManager::RequestEnableNotificationDailog(
    const sptr<NotificationBundleOption>& bundle,
    const sptr<AnsDialogCallback>& callback,
    const sptr<IRemoteObject>& callerToken)
{
    if (bundle == nullptr || callback == nullptr) {
        return ERROR_INTERNAL_ERROR;
    }
    if (!AddDialogInfoIfNotExist(bundle, callback)) {
        ANS_LOGE("AddDialogIfNotExist failed. Dialog already exists.");
        return ERR_ANS_DIALOG_IS_POPPING;
    }
    ErrCode result = NotificationDialog::StartEnableNotificationDialogAbility(
        NotificationDialogManager::NOTIFICATION_DIALOG_SERVICE_BUNDLE,
        NotificationDialogManager::NOTIFICATION_DIALOG_SERVICE_ABILITY,
        bundle->GetUid(),
        callerToken);
    if (result != ERR_OK) {
        ANS_LOGE("StartEnableNotificationDialogAbility failed, result = %{public}d", result);
        std::unique_ptr<NotificationDialogManager::DialogInfo> dialogInfoRemoved = nullptr;
        RemoveDialogInfoByBundleOption(bundle, dialogInfoRemoved);
    }
    return result;
}

ErrCode NotificationDialogManager::OnBundleEnabledStatusChanged(
    DialogStatus status, const std::string& bundleName)
{
    ANS_LOGD("enter");
    bool result = false;
    switch (status) {
        case DialogStatus::ALLOW_CLICKED:
            result = OnDialogButtonClicked(bundleName, true);
            break;
        case DialogStatus::DENY_CLICKED:
            result = OnDialogButtonClicked(bundleName, false);
            break;
        case DialogStatus::DIALOG_CRASHED:
            result = OnDialogCrashed(bundleName);
            break;
        case DialogStatus::DIALOG_SERVICE_DESTROYED:
            result = OnDialogServiceDestroyed();
            break;
        default:
            result = false;
    }
    if (!result) {
        ANS_LOGE("OnBundleEnabledStatusChanged failed");
        return ERROR_INTERNAL_ERROR;
    }
    return ERR_OK;
}

bool NotificationDialogManager::AddDialogInfoIfNotExist(
    const sptr<NotificationBundleOption>& bundle,
    const sptr<AnsDialogCallback>& callback)
{
    std::lock_guard<std::mutex> lock(dialogsMutex_);
    std::string name = bundle->GetBundleName();
    auto dialogIter = std::find_if(dialogsOpening_.begin(), dialogsOpening_.end(),
        [&](const std::unique_ptr<DialogInfo>& dialogInfo) {
            return dialogInfo->bundleOption->GetBundleName() == name;
        });
    if (dialogIter != dialogsOpening_.end()) {
        return false;
    }
    auto dialogInfo = std::make_unique<DialogInfo>();
    dialogInfo->bundleOption = bundle;
    dialogInfo->callback = callback;
    dialogsOpening_.push_back(std::move(dialogInfo));
    return true;
}

sptr<NotificationBundleOption> NotificationDialogManager::GetBundleOptionByBundleName(
    const std::string& bundleName)
{
    std::lock_guard<std::mutex> lock(dialogsMutex_);
    auto dialogIter = std::find_if(dialogsOpening_.begin(), dialogsOpening_.end(),
        [&](const std::unique_ptr<DialogInfo>& dialogInfo) {
            return dialogInfo->bundleOption->GetBundleName() == bundleName;
        });
    if (dialogIter == dialogsOpening_.end()) {
        return nullptr;
    }
    auto result = sptr<NotificationBundleOption>::MakeSptr(*((*dialogIter)->bundleOption));
    return result;
};

void NotificationDialogManager::RemoveDialogInfoByBundleOption(const sptr<NotificationBundleOption>& bundle,
    std::unique_ptr<DialogInfo>& dialogInfoRemoved)
{
    std::lock_guard<std::mutex> lock(dialogsMutex_);
    std::string name = bundle->GetBundleName();
    auto dialogIter = std::find_if(dialogsOpening_.begin(), dialogsOpening_.end(),
        [&](const std::unique_ptr<DialogInfo>& dialogInfo) {
            return dialogInfo->bundleOption->GetBundleName() == name;
        });
    if (dialogIter == dialogsOpening_.end()) {
        dialogInfoRemoved = nullptr;
        return;
    }
    dialogInfoRemoved = std::move(*dialogIter);
    dialogsOpening_.erase(dialogIter);
}

void NotificationDialogManager::RemoveAllDialogInfos(std::list<std::unique_ptr<DialogInfo>>& dialogInfosRemoved)
{
    std::lock_guard<std::mutex> lock(dialogsMutex_);
    for (auto& dialogInfo : dialogsOpening_) {
        dialogInfosRemoved.push_back(std::move(dialogInfo));
    }
    dialogsOpening_.clear();
}

bool NotificationDialogManager::SetHasPoppedDialog(
    const sptr<NotificationBundleOption>& bundleOption, bool hasPopped)
{
    ANS_LOGD("enter");
    if (bundleOption == nullptr) {
        return false;
    }
    ErrCode result = NotificationPreferences::GetInstance().SetHasPoppedDialog(bundleOption, hasPopped);
    return result == ERR_OK;
}

bool NotificationDialogManager::OnDialogButtonClicked(const std::string& bundleName, bool enabled)
{
    ANS_LOGD("enter");
    auto bundleOption = GetBundleOptionByBundleName(bundleName);
    if (bundleOption == nullptr) {
        return false;
    }

    NotificationDialogManager::SetHasPoppedDialog(bundleOption, true);

    ErrCode result = ans_.SetNotificationsEnabledForSpecialBundle(
        NotificationDialogManager::DEFAULT_DEVICE_ID,
        bundleOption, enabled);
    if (result != ERR_OK) {
        ANS_LOGE("SetNotificationsEnabledForSpecialBundle Failed, code is %{public}d", result);
        // Do not return here, need to clear the data
    }
    EnabledDialogStatus status = enabled ? EnabledDialogStatus::ALLOW_CLICKED : EnabledDialogStatus::DENY_CLICKED;
    return HandleOneDialogClosed(bundleOption, status);
}

bool NotificationDialogManager::OnDialogCrashed(const std::string& bundleName)
{
    ANS_LOGD("enter");
    auto bundleOption = GetBundleOptionByBundleName(bundleName);
    if (bundleOption == nullptr) {
        return false;
    }

    ErrCode result = ans_.SetNotificationsEnabledForSpecialBundle(
        NotificationDialogManager::DEFAULT_DEVICE_ID,
        bundleOption, false);
    if (result != ERR_OK) {
        ANS_LOGE("SetNotificationsEnabledForSpecialBundle Failed, code is %{public}d", result);
        // Do not return here, need to clear the data
    }
    return HandleOneDialogClosed(bundleOption, EnabledDialogStatus::CRASHED);
}

bool NotificationDialogManager::OnDialogServiceDestroyed()
{
    ANS_LOGD("enter");
    return HandleAllDialogsClosed();
}

bool NotificationDialogManager::HandleOneDialogClosed(
    sptr<NotificationBundleOption> bundleOption,
    EnabledDialogStatus status)
{
    if (bundleOption == nullptr) {
        return false;
    }
    std::unique_ptr<DialogInfo> dialogInfoRemoved = nullptr;
    RemoveDialogInfoByBundleOption(bundleOption, dialogInfoRemoved);
    if (dialogInfoRemoved != nullptr && dialogInfoRemoved->callback != nullptr) {
        DialogStatusData statusData(status);
        dialogInfoRemoved->callback->OnDialogStatusChanged(statusData);
    }
    return true;
}

bool NotificationDialogManager::HandleAllDialogsClosed()
{
    std::list<std::unique_ptr<DialogInfo>> dialogInfosRemoved;
    RemoveAllDialogInfos(dialogInfosRemoved);
    for (auto& dialogInfoSP : dialogInfosRemoved) {
        if (dialogInfoSP != nullptr && dialogInfoSP->callback != nullptr) {
            DialogStatusData statusData(EnabledDialogStatus::CRASHED);
            dialogInfoSP->callback->OnDialogStatusChanged(statusData);
        }
    }
    return true;
}

} // namespace OHOS::Notification
