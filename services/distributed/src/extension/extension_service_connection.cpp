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

#include "ability_manager_client.h"
#include "extension_service_connection.h"
#include "extension_service_connection_service.h"
#include "extension_service_connection_timer_info.h"
#include "extension_service.h"
#include "in_process_call_wrapper.h"
#include "notification_analytics_util.h"
#include "notification_helper.h"
#include "time_service_client.h"

#ifdef RESOURCE_SCHEDULE_SERVICE_ENABLE
#include "app_mgr_interface.h"
#include "app_mgr_constants.h"
#include "bundle_info.h"
#include "iservice_registry.h"
#include "res_sched_client.h"
#include "resource_type.h"
#include "system_ability_definition.h"
#endif

namespace OHOS {
namespace Notification {
namespace {
constexpr const int64_t MS_PER_SECOND = 1000;
constexpr const uint32_t FREEZE_PREPARE_TIME = 10;
constexpr const uint32_t DEFAULT_DISCONNECT_DELAY_TIME = 1800;  //default: 30m
}
uint32_t ExtensionServiceConnection::DISCONNECT_DELAY_TIME = DEFAULT_DISCONNECT_DELAY_TIME;

ExtensionServiceConnection::ExtensionServiceConnection(const ExtensionSubscriberInfo& subscriberInfo,
    std::function<void(const ExtensionSubscriberInfo& subscriberInfo)> onDisconnected)
    : subscriberInfo_(subscriberInfo), onDisconnected_(onDisconnected)
{
    auto timerClient = MiscServices::TimeServiceClient::GetInstance();
    if (timerClient == nullptr) {
        ANS_LOGE("null TimeServiceClient");
        return;
    }
    wptr<ExtensionServiceConnection> wThis = this;
    auto timerInfoFreeze = std::make_shared<ExtensionServiceConnectionTimerInfo>([wThis] {
        sptr<ExtensionServiceConnection> sThis = wThis.promote();
        if (!sThis) {
            return;
        }
        IN_PROCESS_CALL_WITHOUT_RET(sThis->Freeze());
    });
    timerIdFreeze_ = timerClient->CreateTimer(timerInfoFreeze);
    auto timerInfoDisconnect = std::make_shared<ExtensionServiceConnectionTimerInfo>([wThis] {
        sptr<ExtensionServiceConnection> sThis = wThis.promote();
        if (!sThis) {
            return;
        }
        IN_PROCESS_CALL_WITHOUT_RET(sThis->Disconnect());
    });
    timerIdDisconnect_ = timerClient->CreateTimer(timerInfoDisconnect);
}

ExtensionServiceConnection::~ExtensionServiceConnection()
{}

void ExtensionServiceConnection::Close()
{
    std::lock_guard<ffrt::recursive_mutex> lock(mutex_);
    ANS_LOGD("Close %{public}s", subscriberInfo_.GetKey().c_str());
    auto timerClient = MiscServices::TimeServiceClient::GetInstance();
    if (timerClient == nullptr) {
        ANS_LOGE("null TimeServiceClient");
        return;
    }

    timerClient->DestroyTimer(timerIdFreeze_);
    timerIdFreeze_ = 0L;
    timerClient->DestroyTimer(timerIdDisconnect_);
    timerIdDisconnect_ = 0L;
    if (state_ == ExtensionServiceConnectionState::CREATED ||
        state_ == ExtensionServiceConnectionState::DISCONNECTED) {
        HandleDisconnectedState();
    } else {
        AAFwk::AbilityManagerClient::GetInstance()->DisconnectAbility(this);
    }
}

void ExtensionServiceConnection::NotifyOnReceiveMessage(const sptr<NotificationRequest> notificationRequest)
{
    if (notificationRequest == nullptr) {
        ANS_LOGE("null notificationRequest");
        return;
    }
    std::lock_guard<ffrt::recursive_mutex> lock(mutex_);
    ANS_LOGD("%{public}s", subscriberInfo_.GetKey().c_str());
    if (state_ == ExtensionServiceConnectionState::DISCONNECTED) {
        return;
    }
    if (state_ == ExtensionServiceConnectionState::CREATED ||
        state_ == ExtensionServiceConnectionState::CONNECTING) {
        NotifyParam param = { .notificationRequest = notificationRequest };
        messages_.emplace_back(NotifyType::OnReceiveMessage, param);
        ANS_LOGD("Cache OnReceiveMessage");
        if (state_ == ExtensionServiceConnectionState::CREATED) {
            ANS_LOGD("Connect ability");
            state_ = ExtensionServiceConnectionState::CONNECTING;
            AAFwk::Want want;
            want.SetElementName(subscriberInfo_.bundleName, subscriberInfo_.extensionName);
            AAFwk::AbilityManagerClient::GetInstance()->ConnectAbility(want, this, subscriberInfo_.userId);
        }
        return;
    }
    Unfreeze();
    if (proxy_ == nullptr) {
        ANS_LOGE("null proxy_");
    } else {
        int32_t retResult = 0;
        ErrCode callResult = proxy_->OnReceiveMessage(notificationRequest, retResult);
        ANS_LOGI("%{public}s OnReceiveMessage callResult %{public}d retResult %{public}d",
            subscriberInfo_.GetKey().c_str(), callResult, retResult);
        std::string message = subscriberInfo_.bundleName + ", " +
            std::to_string(subscriberInfo_.uid) +
            " receive message " + notificationRequest->GetNotificationHashCode();
        AppendMessage(message, callResult, retResult);
        NotificationExtensionService::GetInstance().SendHaReport(
            EventSceneId::SCENE_27, EventBranchId::BRANCH_8, 0, message);
    }
    PrepareFreeze();
    PrepareDisconnect();
}

void ExtensionServiceConnection::NotifyOnCancelMessages(const std::shared_ptr<std::vector<std::string>> hashCodes)
{
    if (hashCodes == nullptr) {
        ANS_LOGE("null hashCodes");
        return;
    }
    std::lock_guard<ffrt::recursive_mutex> lock(mutex_);
    if (state_ == ExtensionServiceConnectionState::DISCONNECTED) {
        return;
    }
    if (state_ == ExtensionServiceConnectionState::CREATED ||
        state_ == ExtensionServiceConnectionState::CONNECTING) {
        NotifyParam param = { .hashCodes = hashCodes };
        messages_.emplace_back(NotifyType::OnCancelMessages, param);
        ANS_LOGD("Cache OnCancelMessages");
        if (state_ == ExtensionServiceConnectionState::CREATED) {
            ANS_LOGD("Connect ability");
            state_ = ExtensionServiceConnectionState::CONNECTING;
            AAFwk::Want want;
            want.SetElementName(subscriberInfo_.bundleName, subscriberInfo_.extensionName);
            AAFwk::AbilityManagerClient::GetInstance()->ConnectAbility(want, this, subscriberInfo_.userId);
        }
        return;
    }
    Unfreeze();
    if (proxy_ == nullptr) {
        ANS_LOGE("null proxy_");
    } else {
        int32_t retResult = 0;
        ErrCode callResult = proxy_->OnCancelMessages(*hashCodes, retResult);
        ANS_LOGI("%{public}s OnCancelMessages callResult %{public}d retResult %{public}d",
            subscriberInfo_.GetKey().c_str(), callResult, retResult);
        std::string message = subscriberInfo_.bundleName + ", " +
            std::to_string(subscriberInfo_.uid) +
            " cancel message size " + std::to_string(hashCodes->size());
        AppendMessage(message, callResult, retResult);
        NotificationExtensionService::GetInstance().SendHaReport(
            EventSceneId::SCENE_27, EventBranchId::BRANCH_9, 0, message);
    }
    PrepareFreeze();
    PrepareDisconnect();
}

void ExtensionServiceConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    std::lock_guard<ffrt::recursive_mutex> lock(mutex_);
    ANS_LOGD("%{public}s", subscriberInfo_.GetKey().c_str());
    wptr<ExtensionServiceConnection> wThis = this;
    deathRecipient_ = new (std::nothrow) RemoteDeathRecipient([wThis] (const wptr<IRemoteObject> &remote) {
        sptr<ExtensionServiceConnection> sThis = wThis.promote();
        if (sThis == nullptr) {
            return;
        }
        std::lock_guard<ffrt::recursive_mutex> lock(sThis->mutex_);
        ANS_LOGI("OnRemoteDied %{public}s", sThis->subscriberInfo_.GetKey().c_str());
        sThis->state_ = ExtensionServiceConnectionState::DISCONNECTED;
        sThis->Close();
    });
    if (deathRecipient_ == nullptr) {
        ANS_LOGE("Failed to create RemoteDeathRecipient instance");
    }
    state_ = ExtensionServiceConnectionState::CONNECTED;
    remoteObject_ = remoteObject;
    remoteObject->AddDeathRecipient(deathRecipient_);
    proxy_ = new (std::nothrow) NotificationSubscriberProxy(remoteObject);
    if (proxy_ == nullptr) {
        ANS_LOGE("failed to create NotificationSubscriberProxy!");
    }
    std::string message = subscriberInfo_.bundleName + ", " + std::to_string(subscriberInfo_.uid) + " connect";
    NotificationExtensionService::GetInstance().SendHaReport(
        EventSceneId::SCENE_27, EventBranchId::BRANCH_10, 0, message);
    GetPid();

    for (auto& message : messages_) {
        switch (message.first) {
            case NotifyType::OnReceiveMessage:
                NotifyOnReceiveMessage(message.second.notificationRequest);
                break;
            case NotifyType::OnCancelMessages:
                NotifyOnCancelMessages(message.second.hashCodes);
                break;
            default:
                ANS_LOGW("incorrect type");
                break;
        }
    }
    messages_.clear();
}

void ExtensionServiceConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    std::lock_guard<ffrt::recursive_mutex> lock(mutex_);
    ANS_LOGD("OnAbilityDisconnectDone %{public}s", subscriberInfo_.GetKey().c_str());
    state_ = ExtensionServiceConnectionState::DISCONNECTED;
    pid_ = -1;
    HandleDisconnectedState();
}

void ExtensionServiceConnection::SetExtensionLifecycleDestroyTime(uint32_t value)
{
    if (value < FREEZE_PREPARE_TIME) {
        DISCONNECT_DELAY_TIME = DEFAULT_DISCONNECT_DELAY_TIME;
        ANS_LOGW("invalid destroy time, using default");
    } else {
        DISCONNECT_DELAY_TIME = value;
    }
}

void ExtensionServiceConnection::PrepareFreeze()
{
    std::lock_guard<ffrt::recursive_mutex> lock(mutex_);
    ANS_LOGD("PrepareFreeze %{public}s", subscriberInfo_.GetKey().c_str());
    if (state_ != ExtensionServiceConnectionState::CONNECTED) {
        ANS_LOGD("state not match: %{public}d", static_cast<int32_t>(state_));
        return;
    }

    auto timerClient = MiscServices::TimeServiceClient::GetInstance();
    if (timerClient == nullptr) {
        ANS_LOGE("null TimeServiceClient");
        return;
    }

    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    timerClient->StartTimer(timerIdFreeze_, duration.count() + FREEZE_PREPARE_TIME * MS_PER_SECOND);
}

void ExtensionServiceConnection::Freeze()
{
    std::lock_guard<ffrt::recursive_mutex> lock(mutex_);
    ANS_LOGD("Freeze %{public}s", subscriberInfo_.GetKey().c_str());
    DoFreezeUnfreeze(true);
}

void ExtensionServiceConnection::Unfreeze()
{
    std::lock_guard<ffrt::recursive_mutex> lock(mutex_);
    ANS_LOGD("Unfreeze %{public}s", subscriberInfo_.GetKey().c_str());
    auto timerClient = MiscServices::TimeServiceClient::GetInstance();
    if (timerClient == nullptr) {
        ANS_LOGE("null TimeServiceClient");
        return;
    }

    timerClient->StopTimer(timerIdFreeze_);
    timerClient->StopTimer(timerIdDisconnect_);

    DoFreezeUnfreeze(false);
}

void ExtensionServiceConnection::PrepareDisconnect()
{
    std::lock_guard<ffrt::recursive_mutex> lock(mutex_);

    ANS_LOGD("%{public}s", subscriberInfo_.GetKey().c_str());
    auto timerClient = MiscServices::TimeServiceClient::GetInstance();
    if (timerClient == nullptr) {
        ANS_LOGE("null TimeServiceClient");
        return;
    }

    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    timerClient->StartTimer(timerIdDisconnect_, duration.count() + DISCONNECT_DELAY_TIME * MS_PER_SECOND);
}

void ExtensionServiceConnection::Disconnect()
{
    std::lock_guard<ffrt::recursive_mutex> lock(mutex_);
    if (remoteObject_ != nullptr) {
        remoteObject_->RemoveDeathRecipient(deathRecipient_);
        remoteObject_ = nullptr;
    }
    ANS_LOGD("Disconnect %{public}s", subscriberInfo_.GetKey().c_str());
    AAFwk::AbilityManagerClient::GetInstance()->DisconnectAbility(this);
}

void ExtensionServiceConnection::GetPid()
{
#ifdef RESOURCE_SCHEDULE_SERVICE_ENABLE
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        ANS_LOGE("get systemAbilityManager failed");
        return;
    }

    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (remoteObject == nullptr) {
        ANS_LOGE("get remoteObject failed");
        return;
    }

    sptr<AppExecFwk::IAppMgr> appMgr = iface_cast<AppExecFwk::IAppMgr>(remoteObject);
    if (appMgr == nullptr) {
        ANS_LOGE("get appMgr failed");
        return;
    }

    std::vector<AppExecFwk::RunningProcessInfo> runningProcessInfos;
    int32_t ret =
        appMgr->GetRunningProcessInformation(subscriberInfo_.bundleName, subscriberInfo_.userId, runningProcessInfos);
    if (ret != ERR_OK) {
        ANS_LOGE("GetRunningProcessInformation ret %{public}d", ret);
        return;
    }
    if (runningProcessInfos.size() == 0) {
        ANS_LOGE("empty runningProcessInfos");
        return;
    }

    for (const auto& info : runningProcessInfos) {
        if (info.processType_ == AppExecFwk::ProcessType::EXTENSION &&
            info.extensionType_ == AppExecFwk::ExtensionAbilityType::NOTIFICATION_SUBSCRIBER &&
            info.uid_ == subscriberInfo_.uid) {
            pid_ = info.pid_;
            ANS_LOGI("Init pid success: %{public}d", pid_);
            return;
        }
    }
#endif
}

void ExtensionServiceConnection::DoFreezeUnfreeze(bool isFreeze)
{
#ifdef RESOURCE_SCHEDULE_SERVICE_ENABLE
    if (isFreeze) {
        ANS_LOGD("Do Freeze pid:%{public}d", pid_);
    } else {
        ANS_LOGD("Do Unfreeze pid:%{public}d", pid_);
    }
    auto type = ResourceSchedule::ResType::RES_TYPE_SA_CONTROL_APP_EVENT;
    auto status = isFreeze ?
        ResourceSchedule::ResType::SaControlAppStatus::SA_STOP_APP :
        ResourceSchedule::ResType::SaControlAppStatus::SA_START_APP;
    std::unordered_map<std::string, std::string> payload = {
        { "saId", std::to_string(static_cast<int32_t>(ADVANCED_NOTIFICATION_SERVICE_ABILITY_ID)) },
        { "saName", "distributed_notification_service" },
        { "extensionType",
            std::to_string(static_cast<int32_t>(AppExecFwk::ExtensionAbilityType::NOTIFICATION_SUBSCRIBER)) },
        { "pid", std::to_string(pid_) },
        { "resourceFlags", std::to_string(BackgroundTaskMgr::ResourceType::Type::BLUETOOTH) }, { "isApply", "1" } };
    ResourceSchedule::ResSchedClient::GetInstance().ReportData(type, status, payload);
#endif
}

void ExtensionServiceConnection::HandleDisconnectedState()
{
    if (remoteObject_ != nullptr) {
        remoteObject_->RemoveDeathRecipient(deathRecipient_);
        remoteObject_ = nullptr;
    }
    proxy_ = nullptr;
    if (onDisconnected_) {
        ANS_LOGD("call onDisconnected %{public}s", subscriberInfo_.GetKey().c_str());
        onDisconnected_(subscriberInfo_);
        onDisconnected_ = nullptr;
    }
}

void ExtensionServiceConnection::AppendMessage(std::string& message, ErrCode callResult, int32_t retResult)
{
    if (callResult != ERR_OK) {
        message += " failed with callResult " + std::to_string(callResult);
    } else if (retResult != ERR_OK) {
        message += " failed with retResult " + std::to_string(retResult);
    } else {
        message += " OK";
    }
}
}
}
