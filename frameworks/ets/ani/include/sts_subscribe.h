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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_SUBSCRIBE_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_SUBSCRIBE_H
#include "ani.h"
#include "notification_request.h"
#include "notification_operation_info.h"
#include "ans_operation_callback_stub.h"
#include "notification_subscriber.h"
#include "notification_do_not_disturb_date.h"

#include "sts_notification_manager.h"
#include "sts_subscriber.h"

namespace OHOS {
namespace NotificationSts {
using NotificationKey = OHOS::Notification::NotificationKey;
using StsNotificationOperationInfo = OHOS::Notification::NotificationOperationInfo;

class StsDistributedOperationCallback : public OHOS::Notification::AnsOperationCallbackStub {
public:
    explicit StsDistributedOperationCallback(ani_object promise, ani_resolver resolver);
    ~StsDistributedOperationCallback() override {};
    ErrCode OnOperationCallback(const int32_t operationResult) override;
    void OnStsOperationCallback(ani_env *env, const int32_t operationResult);
    void SetVm(ani_vm *vm);
private:
    ani_vm *etsVm_;
    ani_resolver resolver_;
    bool isCall_ = false;
    std::mutex lock_;
};

class StsSubscriberInstance : public OHOS::Notification::NotificationSubscriber {
public:
    StsSubscriberInstance(){};
    virtual ~StsSubscriberInstance(){};

    virtual void OnCanceled(const std::shared_ptr<OHOS::Notification::Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override;

    virtual void OnConsumed(const std::shared_ptr<OHOS::Notification::Notification> &request,
        const std::shared_ptr<NotificationSortingMap> &sortingMap) override;

    virtual void OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap) override;

    virtual void OnConnected() override;

    virtual void OnDisconnected() override;

    virtual void OnDied() override;

    virtual void OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date) override;

    void onDoNotDisturbChanged(const std::shared_ptr<NotificationDoNotDisturbDate> &date);

    virtual void OnEnabledNotificationChanged(
        const std::shared_ptr<EnabledNotificationCallbackData> &callbackData) override;

    void OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData) override;

    void OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData) override;

    virtual void OnBatchCanceled(const std::vector<std::shared_ptr<OHOS::Notification::Notification>> &requestList,
        const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason) override;

    virtual bool HasOnBatchCancelCallback() override;

    bool SetObject(ani_env *env, ani_object obj);
    bool IsInit();
    bool Compare(ani_env *env, ani_object obj);
    bool Compare(ani_env *env, ani_ref ref);

private:
    bool CallFunction(ani_env *env, const char* func, std::vector<ani_ref> &parm);

private:
    ani_ref ref_ = nullptr;
    ani_object obj_ = nullptr;
    ani_vm *vm_ = nullptr;
    std::mutex lock_;
};

class SubscriberInstanceManager {
public:
    static SubscriberInstanceManager* GetInstance()
    {
        static SubscriberInstanceManager instance;
        return &instance;
    }
    ~SubscriberInstanceManager() = default;

    bool HasNotificationSubscriber(
        ani_env *env, ani_object value, std::shared_ptr<StsSubscriberInstance> &subscriberInfo);
    bool AddSubscriberInstancesInfo(ani_env *env, std::shared_ptr<StsSubscriberInstance> &subscriberInfo);
    bool DelSubscriberInstancesInfo(ani_env *env, ani_ref ref);

    bool AddDeletingSubscriber(std::shared_ptr<StsSubscriberInstance> subscriber);
    void DelDeletingSubscriber(std::shared_ptr<StsSubscriberInstance> subscriber);

    bool Subscribe(ani_env *env, ani_object subscriber, ani_object info);
    bool SubscribeSelf(ani_env *env, ani_object subscriber);
    bool UnSubscribe(ani_env *env, ani_object subscriber);
private:
    SubscriberInstanceManager() {}

    bool GetNotificationSubscriber(
        ani_env *env, ani_object value, std::shared_ptr<StsSubscriberInstance> &subscriberInfo);

private:
    std::mutex mutex_;
    std::vector<std::shared_ptr<StsSubscriberInstance>> subscriberInstances_;
    std::mutex delMutex_;
    std::vector<std::shared_ptr<StsSubscriberInstance>> DeletingSubscriber;
};

bool IsValidRemoveReason(int32_t reasonType);
bool UnWarpReasonEnum(ani_env *env, const ani_object enumItem, int32_t &outEnum);
bool UnWarpNotificationKey(ani_env *env, const ani_object obj, NotificationKey &OutObj);
bool UnwarpOperationInfo(ani_env *env, const ani_object obj, StsNotificationOperationInfo &outObj);
sptr<StsNotificationOperationInfo> GetOperationInfoForDistributeOperation(
    ani_env *env, ani_string hashcode, ani_object operationInfo, bool &noWithOperationInfo);
} // namespace NotificationSts
} // OHOS
#endif