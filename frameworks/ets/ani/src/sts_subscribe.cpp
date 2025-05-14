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
#include "sts_subscribe.h"

#include "ans_log_wrapper.h"
#include "inner_errors.h"
#include "notification_helper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "sts_sorting_map.h"
#include "sts_subscribe_info.h"

namespace OHOS {
namespace NotificationSts {
StsDistributedOperationCallback::StsDistributedOperationCallback(ani_object promise, ani_resolver resolver)
:resolver_(resolver)
{
}

void StsDistributedOperationCallback::OnOperationCallback(const int32_t operationResult)
{
    std::lock_guard<std::mutex> l(lock_);
    if (isCall_) return;
    ANS_LOGD("OnOperationCallback ENTER");
    int32_t externalCode = OHOS::CJSystemapi::Notification::ErrorToExternal(operationResult);
    ANS_LOGD("operationResult %{public}d, externalCode %{public}d", operationResult, externalCode);
    if (etsVm_ == nullptr) {
        ANS_LOGD("etsVm_ is null");
        return;
    }
    ani_env* etsEnv;
    ani_status aniResult = ANI_ERROR;
    ani_options aniArgs { 0, nullptr };
    aniResult = etsVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv);
    if (aniResult != ANI_OK) {
        ANS_LOGD("StsDistributedOperationCallback AttachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }

    if (operationResult == 0) {
        ANS_LOGD("OnOperationCallback Resolve");
        ani_ref ref {};
        if (ANI_OK != (aniResult = etsEnv->PromiseResolver_Resolve(resolver_, ref))) {
            ANS_LOGD("PromiseResolver_Resolve faild. status %{public}d", aniResult);
        }
    } else {
        ANS_LOGD("OnOperationCallback reject");
        std::string errMsg = FindAnsErrMsg(externalCode);
        ani_error rejection = static_cast<ani_error>(OHOS::AbilityRuntime::CreateStsError(etsEnv, externalCode, errMsg));
        if (ANI_OK != (aniResult = etsEnv->PromiseResolver_Reject(resolver_, rejection))) {
            ANS_LOGD("PromiseResolver_Resolve faild. status %{public}d", aniResult);
        }
    }
    aniResult = etsVm_->DetachCurrentThread();
    if (aniResult != ANI_OK) {
        ANS_LOGD("StsDistributedOperationCallback DetachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
    isCall_ = true;
}

void StsDistributedOperationCallback::SetVm(ani_vm *vm)
{
    etsVm_ = vm;
}

StsSubscriberInstance::StsSubscriberInstance()
{}
StsSubscriberInstance::~StsSubscriberInstance()
{}
void StsSubscriberInstance::OnCanceled(
    const std::shared_ptr<OHOS::Notification::Notification> &request,
    const std::shared_ptr<NotificationSortingMap> &sortingMap,
    int32_t deleteReason)
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> l(lock_);
    ani_env* etsEnv;
    ani_status aniResult = ANI_ERROR;
    ani_options aniArgs { 0, nullptr };
    aniResult = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv);
    if (aniResult != ANI_OK) {
        ANS_LOGD("AttachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
    std::vector<ani_ref> vec;
    ani_object obj;
    if (WarpSubscribeCallbackData(etsEnv, request, sortingMap, deleteReason, obj)) {
        vec.push_back(obj);
        CallFunction(etsEnv, "onCancel", vec);
    } else {
        ANS_LOGD("WarpSubscribeCallbackData faild");
    }
    aniResult = vm_->DetachCurrentThread();
    if (aniResult != ANI_OK) {
        ANS_LOGD("DetachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
}
void StsSubscriberInstance::OnConsumed(
    const std::shared_ptr<OHOS::Notification::Notification> &request,
    const std::shared_ptr<NotificationSortingMap> &sortingMap)
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> l(lock_);
    ani_env* etsEnv;
    ani_status aniResult = ANI_ERROR;
    ani_options aniArgs { 0, nullptr };
    aniResult = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv);
    if (aniResult != ANI_OK) {
        ANS_LOGD("AttachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
    std::vector<ani_ref> vec;
    ani_object obj;
    if (WarpSubscribeCallbackData(etsEnv, request, sortingMap, -1, obj)) {
        vec.push_back(obj);
        CallFunction(etsEnv, "onConsume", vec);
    } else {
        ANS_LOGD("WarpSubscribeCallbackData faild");
    }
    aniResult = vm_->DetachCurrentThread();
    if (aniResult != ANI_OK) {
        ANS_LOGD("DetachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
}
void StsSubscriberInstance::OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap)
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> l(lock_);
    ani_env* etsEnv;
    ani_status aniResult = ANI_ERROR;
    ani_options aniArgs { 0, nullptr };
    aniResult = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv);
    if (aniResult != ANI_OK) {
        ANS_LOGD("AttachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
    std::vector<ani_ref> vec;
    ani_object obj;
    if (WarpNotificationSortingMap(etsEnv, sortingMap, obj)) {
        vec.push_back(obj);
        CallFunction(etsEnv, "onUpdate", vec);
    } else {
        ANS_LOGD("WarpNotificationSortingMap faild");
    }
    aniResult = vm_->DetachCurrentThread();
    if (aniResult != ANI_OK) {
        ANS_LOGD("DetachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
}
void StsSubscriberInstance::OnConnected()
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> l(lock_);
    ani_env* etsEnv;
    ani_status aniResult = ANI_ERROR;
    ani_options aniArgs { 0, nullptr };
    aniResult = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv);
    if (aniResult != ANI_OK) {
        ANS_LOGD("AttachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
    std::vector<ani_ref> vec;
    CallFunction(etsEnv, "onConnect", vec);
    aniResult = vm_->DetachCurrentThread();
    if (aniResult != ANI_OK) {
        ANS_LOGD("DetachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
}
void StsSubscriberInstance::OnDisconnected()
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> l(lock_);
    ani_env* etsEnv;
    ani_status aniResult = ANI_ERROR;
    ani_options aniArgs { 0, nullptr };
    aniResult = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv);
    if (aniResult != ANI_OK) {
        ANS_LOGD("AttachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
    std::vector<ani_ref> vec;
    CallFunction(etsEnv, "onDisconnect", vec);
    if (!SubscriberInstanceManager::GetInstance()->DelSubscriberInstancesInfo(etsEnv, obj_)) {
        ANS_LOGD("DelSubscriberInstancesInfo faild");
    } else {
        ANS_LOGD("DelSubscriberInstancesInfo suc..");
    }
    aniResult = vm_->DetachCurrentThread();
    if (aniResult != ANI_OK) {
        ANS_LOGD("DetachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
}
void StsSubscriberInstance::OnDied()
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> l(lock_);
    ani_env* etsEnv;
    ani_status aniResult = ANI_ERROR;
    ani_options aniArgs { 0, nullptr };
    aniResult = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv);
    if (aniResult != ANI_OK) {
        ANS_LOGD("AttachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
    std::vector<ani_ref> vec;
    CallFunction(etsEnv, "onDestroy", vec);
    aniResult = vm_->DetachCurrentThread();
    if (aniResult != ANI_OK) {
        ANS_LOGD("DetachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
}
void StsSubscriberInstance::OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> l(lock_);
}
void StsSubscriberInstance::onDoNotDisturbChanged(const std::shared_ptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> l(lock_);
    ani_env* etsEnv;
    ani_status aniResult = ANI_ERROR;
    ani_options aniArgs { 0, nullptr };
    aniResult = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv);
    if (aniResult != ANI_OK) {
        ANS_LOGD("AttachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
    std::vector<ani_ref> vec;
    ani_object obj;
    if (WarpNotificationDoNotDisturbDate(etsEnv, date, obj)) {
        vec.push_back(obj);
        CallFunction(etsEnv, "onDoNotDisturbChanged", vec);
    } else {
        ANS_LOGD("WarpNotificationDoNotDisturbDate faild");
    }
    aniResult = vm_->DetachCurrentThread();
    if (aniResult != ANI_OK) {
        ANS_LOGD("DetachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
}
void StsSubscriberInstance::OnEnabledNotificationChanged(
    const std::shared_ptr<EnabledNotificationCallbackData> &callbackData)
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> l(lock_);
    ani_env* etsEnv;
    ani_status aniResult = ANI_ERROR;
    ani_options aniArgs { 0, nullptr };
    aniResult = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv);
    if (aniResult != ANI_OK) {
        ANS_LOGD("AttachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
    std::vector<ani_ref> vec;
    ani_object obj;
    if (WarpEnabledNotificationCallbackData(etsEnv, callbackData, obj)) {
        vec.push_back(obj);
        CallFunction(etsEnv, "onEnabledNotificationChanged", vec);
    } else {
        ANS_LOGD("WarpEnabledNotificationCallbackData faild");
    }
    aniResult = vm_->DetachCurrentThread();
    if (aniResult != ANI_OK) {
        ANS_LOGD("DetachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
}
void StsSubscriberInstance::OnBadgeChanged(const std::shared_ptr<BadgeNumberCallbackData> &badgeData)
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> l(lock_);
    ani_env* etsEnv;
    ani_status aniResult = ANI_ERROR;
    ani_options aniArgs { 0, nullptr };
    aniResult = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv);
    if (aniResult != ANI_OK) {
        ANS_LOGD("AttachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
    std::vector<ani_ref> vec;
    ani_object obj;
    if (WarpBadgeNumberCallbackData(etsEnv, badgeData, obj)) {
        vec.push_back(obj);
        CallFunction(etsEnv, "onBadgeChanged", vec);
    } else {
        ANS_LOGD("WarpBadgeNumberCallbackData faild");
    }
    aniResult = vm_->DetachCurrentThread();
    if (aniResult != ANI_OK) {
        ANS_LOGD("DetachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
}
void StsSubscriberInstance::OnBadgeEnabledChanged(const sptr<EnabledNotificationCallbackData> &callbackData)
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> l(lock_);
    ani_env* etsEnv;
    ani_status aniResult = ANI_ERROR;
    ani_options aniArgs { 0, nullptr };
    aniResult = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv);
    if (aniResult != ANI_OK) {
        ANS_LOGD("AttachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
    std::vector<ani_ref> vec;
    ani_object obj;
    std::shared_ptr<EnabledNotificationCallbackData> data = std::make_shared<EnabledNotificationCallbackData>();
    data->SetBundle(callbackData->GetBundle());
    data->SetUid(callbackData->GetUid());
    data->SetEnable(callbackData->GetEnable());
    if (WarpEnabledNotificationCallbackData(etsEnv, data, obj)) {
        vec.push_back(obj);
        CallFunction(etsEnv, "onBadgeEnabledChanged", vec);
    } else {
        ANS_LOGD("WarpEnabledNotificationCallbackData faild");
    }
    aniResult = vm_->DetachCurrentThread();
    if (aniResult != ANI_OK) {
        ANS_LOGD("DetachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
}
void StsSubscriberInstance::OnBatchCanceled(
    const std::vector<std::shared_ptr<OHOS::Notification::Notification>> &requestList,
    const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason)
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> l(lock_);
    ani_env* etsEnv;
    ani_status aniResult = ANI_ERROR;
    ani_options aniArgs { 0, nullptr };
    aniResult = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv);
    if (aniResult != ANI_OK) {
        ANS_LOGD("AttachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
    std::vector<ani_ref> vec;
    ani_object obj;
    if (WarpSubscribeCallbackDataArray(etsEnv, requestList, sortingMap, deleteReason, obj)) {
        vec.push_back(obj);
        CallFunction(etsEnv, "onBatchCancel", vec);
    } else {
        ANS_LOGD("WarpSubscribeCallbackDataArray faild");
    }
    aniResult = vm_->DetachCurrentThread();
    if (aniResult != ANI_OK) {
        ANS_LOGD("DetachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
}
bool StsSubscriberInstance::HasOnBatchCancelCallback()
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> l(lock_);
    ani_env* etsEnv;
    ani_status aniResult = ANI_ERROR;
    ani_options aniArgs { 0, nullptr };
    aniResult = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv);
    if (aniResult != ANI_OK) {
        ANS_LOGD("AttachCurrentThread error. result: %{public}d.", aniResult);
        return false;
    }
    
    ani_ref fn_ref;
    aniResult = etsEnv->Object_GetFieldByName_Ref(static_cast<ani_object>(ref_), "onBatchCancel", &fn_ref);
    if (ANI_OK != aniResult) {
        ANS_LOGD("Object_GetFieldByName_Ref 'onBatchCancel' error. result: %{public}d.", aniResult);
        vm_->DetachCurrentThread();
        return false;
    }
    ani_boolean isUndefined = true;
    if (ANI_OK != etsEnv->Reference_IsUndefined(fn_ref, &isUndefined)) {
        ANS_LOGD("Reference_IsUndefined  faild");
        vm_->DetachCurrentThread();
        return false;
    }
    aniResult = vm_->DetachCurrentThread();
    if (aniResult != ANI_OK) {
        ANS_LOGD("StsDistributedOperationCallback DetachCurrentThread error. result: %{public}d.", aniResult);
    }
    if (isUndefined == ANI_FALSE) {
        return true;
    }
    return false;
}
bool StsSubscriberInstance::SetObject(ani_env *env, ani_object obj)
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> l(lock_);
    if (env == nullptr || obj == nullptr) return false;
    if (ANI_OK != env->GetVM(&vm_)) {
        ANS_LOGD("GetVM faild");
        return false;
    }
    if (ANI_OK != env->GlobalReference_Create(obj, &ref_)) {
        ANS_LOGD("GlobalReference_Create faild");
        return false;
    }
    obj_ = obj;
    return true;
}
bool StsSubscriberInstance::IsInit()
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> l(lock_);
    return (ref_ != nullptr && vm_ != nullptr);
}
bool StsSubscriberInstance::Compare(ani_env *env, ani_object obj)
{
    ANS_LOGD("enter");
    if (!IsInit()) return false;
    if (obj == nullptr || env == nullptr) return false;
    ani_ref ref;
    if (env->GlobalReference_Create(obj, &ref) != ANI_OK) return false;
    ani_boolean result = ANI_FALSE;
    env->Reference_StrictEquals(ref, ref_, &result);
    env->GlobalReference_Delete(ref);
    return (result == ANI_TRUE) ? true : false;
}
bool StsSubscriberInstance::Compare(std::shared_ptr<StsSubscriberInstance> instance)
{
    ANS_LOGD("enter");
    if (instance == nullptr) return false;
    if (instance->obj_ == obj_) {
        ANS_LOGD("Compare is ture");
        return true;
    }
    ANS_LOGD("Compare is false");
    return false;
}
bool StsSubscriberInstance::CallFunction(ani_env *env, const char *func, std::vector<ani_ref> &parm)
{
    ANS_LOGD("enter");
    if (env == nullptr) return false;
    ani_ref fn_ref;
    ani_status aniResult = env->Object_GetFieldByName_Ref(static_cast<ani_object>(ref_), func, &fn_ref);
    if (ANI_OK != aniResult) {
        ANS_LOGD("Object_GetFieldByName_Ref '%{public}s' error. result: %{public}d.", func, aniResult);
        return false;
    }
    ani_boolean flag = false;
    if (ANI_OK != env->Reference_IsUndefined(fn_ref, &flag)) {
        ANS_LOGD("Reference_IsUndefined  faild");
    }
    ANS_LOGD("[%{public}s] %{public}d. %{public}d", __func__, __LINE__, (int32_t)flag);
    ani_ref fnReturnVal;
    aniResult = env->FunctionalObject_Call(
        static_cast<ani_fn_object>(fn_ref), parm.size(), parm.data(), &fnReturnVal);
    if (ANI_OK != aniResult) {
        ANS_LOGD("FunctionalObject_Call error. result: %{public}d.", aniResult);
        return false;
    }
    ANS_LOGD("[%{public}s] %{public}d", __func__, __LINE__);
    return true;
}

bool SubscriberInstanceManager::HasNotificationSubscriber(
        ani_env *env, ani_object value, std::shared_ptr<StsSubscriberInstance> &subscriberInfo)
    {
        ANS_LOGD("enter");
        for (auto &iter : subscriberInstances_) {
            if (iter->Compare(env, value)) {
                subscriberInfo = iter;
                return true;
            }
        }
        return false;
    }

    bool SubscriberInstanceManager::AddSubscriberInstancesInfo(
        ani_env *env, std::shared_ptr<StsSubscriberInstance> &subscriberInfo)
    {
        ANS_LOGD("enter");
        if (!subscriberInfo->IsInit()) {
            ANS_LOGE("subscriberInfo not init");
            return false;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        subscriberInstances_.emplace_back(subscriberInfo);
        return true;
    }

    bool SubscriberInstanceManager::DelSubscriberInstancesInfo(
        ani_env *env, ani_object obj)
    {
        ANS_LOGD("enter");
        if (obj == nullptr) {
            ANS_LOGE("obj is null");
            return false;
        }

        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = subscriberInstances_.begin(); it != subscriberInstances_.end(); ++it) {
            if ((*it)->Compare(env, obj)) {
                DelDeletingSubscriber((*it));
                subscriberInstances_.erase(it);
                return true;
            }
        }
        return false;
    }

    bool SubscriberInstanceManager::GetNotificationSubscriber(
        ani_env *env, ani_object value, std::shared_ptr<StsSubscriberInstance> &subscriberInfo)
    {
        ANS_LOGD("enter");
        subscriberInfo = std::make_shared<StsSubscriberInstance>();
        if (!subscriberInfo->SetObject(env, value)) {
            ANS_LOGD("SetObject faild");
            return false;
        }
        return true;
    }

    bool SubscriberInstanceManager::AddDeletingSubscriber(std::shared_ptr<StsSubscriberInstance> subscriber)
    {
        ANS_LOGD("enter");
        std::lock_guard<std::mutex> lock(delMutex_);
        if (subscriber == nullptr) return false;
        auto iter = std::find(DeletingSubscriber.begin(), DeletingSubscriber.end(), subscriber);
        if (iter != DeletingSubscriber.end()) {
            return false;
        }

        DeletingSubscriber.push_back(subscriber);
        return true;
    }

    void SubscriberInstanceManager::DelDeletingSubscriber(std::shared_ptr<StsSubscriberInstance> subscriber)
    {
        ANS_LOGD("enter");
        std::lock_guard<std::mutex> lock(delMutex_);
        auto iter = std::find(DeletingSubscriber.begin(), DeletingSubscriber.end(), subscriber);
        if (iter != DeletingSubscriber.end()) {
            DeletingSubscriber.erase(iter);
        }
    }

    bool SubscriberInstanceManager::Subscribe(ani_env *env, ani_object subscriber, ani_object info)
    {
        ANS_LOGD("enter");
        bool isSubscribeUndefine = IsUndefine(env, subscriber);
        bool isInfoUndefine = IsUndefine(env, info);
        if (isSubscribeUndefine) {
            ANS_LOGD("subscriber is undefine");
            return false;
        }
        sptr<OHOS::Notification::NotificationSubscribeInfo> SubscribeInfo =
            new (std::nothrow) OHOS::Notification::NotificationSubscribeInfo();
        if (!isInfoUndefine) {
            if (!UnwarpNotificationSubscribeInfo(env, info, *SubscribeInfo)) {
                ANS_LOGD("UnwarpNotificationSubscribeInfo faild");
                return false;
            }
        }
        std::shared_ptr<StsSubscriberInstance> stsSubscriber = nullptr;
        if (!HasNotificationSubscriber(env, subscriber, stsSubscriber)) {
            if (!GetNotificationSubscriber(env, subscriber, stsSubscriber)) {
                ANS_LOGD("GetNotificationSubscriber faild");
                return false;
            }
            if (!AddSubscriberInstancesInfo(env, stsSubscriber)) {
                ANS_LOGD("AddSubscriberInstancesInfo faild");
                return false;
            }
        }
        ErrCode status = 0;
        if (!isInfoUndefine) {
            status = NotificationHelper::SubscribeNotification(stsSubscriber, SubscribeInfo);
        } else {
            status = NotificationHelper::SubscribeNotification(stsSubscriber);
        }
        if (status != 0) {
            ANS_LOGD("SubscribeNotification faild. status %{public}d ErrorToExternal %{public}d",
                status, OHOS::CJSystemapi::Notification::ErrorToExternal(status));
            return false;
        }
//        testThread = std::thread([stsSubscriber](){
//            std::shared_ptr<NotificationDoNotDisturbDate> data = std::make_shared<NotificationDoNotDisturbDate>();
//            std::shared_ptr<EnabledNotificationCallbackData> callbackData = std::make_shared<EnabledNotificationCallbackData>();
//            std::shared_ptr<BadgeNumberCallbackData> badgeData = std::make_shared<BadgeNumberCallbackData>();
//            sptr<EnabledNotificationCallbackData> callbackDataSptr = new EnabledNotificationCallbackData();
//
//            std::string groupKeyOverride = "GroupKeyOverride";
//            int32_t importance = 10;
//            uint64_t ranking = 20;
//            int32_t visibleness =30;
//            bool isDisplayBadge = false;
//            bool isHiddenNotification = true;
//            NotificationSorting sorting;
//            sorting.SetGroupKeyOverride(groupKeyOverride);
//            sorting.SetImportance(importance);
//            sorting.SetRanking(ranking);
//            sorting.SetVisiblenessOverride(visibleness);
//            sorting.SetDisplayBadge(isDisplayBadge);
//            sorting.SetHiddenNotification(isHiddenNotification);
//            std::vector<NotificationSorting> VSorting;
//            for (int i = 0; i < 5; i++) {
//                sorting.SetKey(std::to_string(i));
//                VSorting.emplace_back(sorting);
//            }
//            std::shared_ptr<NotificationSortingMap> sortingMap = std::make_shared<NotificationSortingMap>(VSorting);
//            data->SetBeginDate(1746588038);
//            data->SetEndDate(1746588038);
//            data->SetDoNotDisturbType(NotificationConstant::DoNotDisturbType::DAILY);
//            ANS_LOGD("%{public}d", __LINE__);
//            stsSubscriber->onDoNotDisturbChanged(data);
//            ANS_LOGD("%{public}d", __LINE__);
//
//            callbackData->SetBundle("hello world");
//            callbackData->SetUid(10010);
//            callbackData->SetEnable(true);
//            ANS_LOGD("%{public}d", __LINE__);
//            stsSubscriber->OnEnabledNotificationChanged(callbackData);
//            ANS_LOGD("%{public}d", __LINE__);
//
//            badgeData->SetAppInstanceKey("SetAppInstanceKey");
//            badgeData->SetBadgeNumber(10086);
//            badgeData->SetBundle("hello world");
//            badgeData->SetUid(100100);
//            badgeData->SetInstanceKey(111000);
//            ANS_LOGD("%{public}d", __LINE__);
//            stsSubscriber->OnBadgeChanged(badgeData);
//            ANS_LOGD("%{public}d", __LINE__);
//
//            callbackDataSptr->SetBundle("hello world");
//            callbackDataSptr->SetUid(10010);
//            callbackDataSptr->SetEnable(true);
//            ANS_LOGD("%{public}d", __LINE__);
//            stsSubscriber->OnBadgeEnabledChanged(callbackDataSptr);
//            ANS_LOGD("%{public}d", __LINE__);
//
//            stsSubscriber->OnUpdate(sortingMap);
//            ANS_LOGD("%{public}d", __LINE__);
//
//            std::shared_ptr<OHOS::Notification::Notification> request = std::make_shared<OHOS::Notification::Notification>(new NotificationRequest());
//            request->SetRemindType(NotificationConstant::RemindType::DEVICE_IDLE_DONOT_REMIND);
//            stsSubscriber->OnCanceled(request, sortingMap, 123);
//            ANS_LOGD("%{public}d", __LINE__);
//            stsSubscriber->OnConsumed(request, sortingMap);
//
//            ANS_LOGD("%{public}d", __LINE__);
//            std::vector<std::shared_ptr<OHOS::Notification::Notification>> requestLists;
//            requestLists.emplace_back(request);
//            stsSubscriber->OnBatchCanceled(requestLists, sortingMap, 10086);
//            ANS_LOGD("%{public}d", __LINE__);
//        });
//        testThread.detach();
        return true;
    }

    bool SubscriberInstanceManager::UnSubscribe(ani_env *env, ani_object subscriber)
    {
        ANS_LOGD("enter");
        if (IsUndefine(env, subscriber)) {
            return false;
        }
        std::shared_ptr<StsSubscriberInstance> stsSubscriber = nullptr;
        if (!HasNotificationSubscriber(env, subscriber, stsSubscriber)) {
            ANS_LOGD("Subscriber not found");
            // ERR_ANS_INVALID_PARAM
            return false;
        }
        bool ret = AddDeletingSubscriber(stsSubscriber);
        if (ret) {
            int32_t status = NotificationHelper::UnSubscribeNotification(stsSubscriber);
            if (status != 0) {
                ANS_LOGD("errorCode is not ERR_OK. %{public}d ErrorToExternal %{public}d",
                    status, OHOS::CJSystemapi::Notification::ErrorToExternal(status));
                DelDeletingSubscriber(stsSubscriber);
            }
        } else {
            // ERR_ANS_SUBSCRIBER_IS_DELETING
            return false;
        }
        return true;
    }

bool UnWarpReasonEnum(ani_env *env, const ani_object enumItem, int32_t &outEnum)
{
    ani_status status = ANI_ERROR;
    ani_int intValue{};
    status = env->EnumItem_GetValue_Int(static_cast<ani_enum_item>(enumItem), &intValue);
    if (ANI_OK != status) {
        ANS_LOGD("EnumItem_GetValue_Int failed, status : %{public}d", status);
        return false;
    }
    outEnum = static_cast<int32_t>(intValue);
    return true;
}

bool IsValidRemoveReason(int32_t reasonType)
{
    if (reasonType == OHOS::Notification::NotificationConstant::CLICK_REASON_DELETE ||
        reasonType == OHOS::Notification::NotificationConstant::CANCEL_REASON_DELETE) {
        return true;
    }
    ANS_LOGD("Reason %{public}d is an invalid value", reasonType);
    return false;
}

bool UnWarpNotificationKey(ani_env *env, const ani_object obj, NotificationKey &OutObj)
{
    ani_boolean isUndefined = ANI_TRUE;
    ani_double idDouble = 0.0;
    if (GetPropertyDouble(env, obj, "id", isUndefined, idDouble) != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGD("UnWarpNotificationKey GetPropertyDouble id fail");
        return false;
    }
    OutObj.id = static_cast<int32_t>(idDouble);

    std::string label;
    if (GetPropertyString(env, obj, "label", isUndefined, label) != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGD("UnWarpNotificationKey GetPropertyString label fail");
        return false;
    }
    OutObj.label = label;
    ANS_LOGD("UnWarpNotificationKey id: %{public}d, label: %{public}s", OutObj.id, OutObj.label.c_str());
    return true;
}

bool UnwarpOperationInfo(ani_env *env, const ani_object obj, StsNotificationOperationInfo &outObj)
{
    ani_boolean isUndefined = ANI_TRUE;
    std::string actionName;
    std::string userInput;
    if (GetPropertyString(env, obj, "actionName", isUndefined, actionName) != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGD("ConvertOperationInfoToNative GetStringOrUndefined actionName fail");
        return false;
    }
    outObj.SetActionName(actionName);
    if (GetPropertyString(env, obj, "userInput", isUndefined, userInput) != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGD("ConvertOperationInfoToNative GetStringOrUndefined userInput fail");
        return false;
    }
    outObj.SetUserInput(actionName);
    ANS_LOGD("ConvertOperationInfoToNative actionName: %{public}s, userInput: %{public}s",
        outObj.GetActionName().c_str(), outObj.GetUserInput().c_str());
    return true;
}

sptr<StsNotificationOperationInfo> GetOperationInfoForDistributeOperation(
    ani_env *env, ani_string hashcode, ani_object operationInfo, bool &noWithOperationInfo)
{
    std::string hashCodeStd;
    sptr<StsNotificationOperationInfo> info = new (std::nothrow) StsNotificationOperationInfo();
    if (ANI_OK != GetStringByAniString(env, hashcode, hashCodeStd)) {
        ANS_LOGD("hashCode is valid");
        return nullptr;
    }
    info->SetHashCode(hashCodeStd);
    noWithOperationInfo = IsUndefine(env, operationInfo);
    if (!noWithOperationInfo) {
        if (!UnwarpOperationInfo(env, operationInfo, *info)) {
            ANS_LOGD("operationInfo is valid");
            return nullptr;
        }
        ANS_LOGD("OperationInfo %{public}s %{public}s",
            info->GetActionName().c_str(), info->GetUserInput().c_str());
        info->SetOperationType(OperationType::DISTRIBUTE_OPERATION_REPLY);
    } else {
        info->SetOperationType(OperationType::DISTRIBUTE_OPERATION_JUMP);
    }
    return info;
}
} // namespace NotificationSts
} // OHOS
