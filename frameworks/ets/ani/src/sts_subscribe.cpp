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
#include "notification_helper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "sts_sorting_map.h"
#include "sts_subscribe_info.h"
#include "ani_common_util.h"
#include <ani_signature_builder.h>

namespace OHOS {
namespace NotificationSts {
using namespace arkts::ani_signature;

StsDistributedOperationCallback::StsDistributedOperationCallback(ani_object promise, ani_resolver resolver)
    : resolver_(resolver)
{
}

ErrCode StsDistributedOperationCallback::OnOperationCallback(const int32_t operationResult)
{
    std::lock_guard<std::mutex> l(lock_);
    if (isCall_) return ANI_OK;
    if (etsVm_ == nullptr) {
        ANS_LOGD("etsVm_ is null");
        return ANI_OK;
    }
    ani_env* etsEnv;
    ani_status aniResult = ANI_ERROR;
    ani_options aniArgs { 0, nullptr };
    aniResult = etsVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv);
    if (aniResult != ANI_OK) {
        ANS_LOGD("StsDistributedOperationCallback AttachCurrentThread error. result: %{public}d.", aniResult);
        return aniResult;
    }
    OnStsOperationCallback(etsEnv, operationResult);
    aniResult = etsVm_->DetachCurrentThread();
    if (aniResult != ANI_OK) {
        ANS_LOGD("StsDistributedOperationCallback DetachCurrentThread error. result: %{public}d.", aniResult);
        return aniResult;
    }
    isCall_ = true;
    return ANI_OK;
}

void StsDistributedOperationCallback::OnStsOperationCallback(ani_env *env, const int32_t operationResult)
{
    ANS_LOGD("ENTER");
    if (env == nullptr) {
        ANS_LOGD("env is nullptr");
        return;
    }
    ani_status status = ANI_OK;
    int32_t externalErrCode = (operationResult == ERR_OK) ? operationResult : GetExternalCode(operationResult);
    ANS_LOGD("operationResult %{public}d, externalCode %{public}d", operationResult, externalErrCode);

    if (externalErrCode == ERR_OK) {
        ANS_LOGD("OnStsOperationCallback Resolve");
        ani_object ret = OHOS::AppExecFwk::CreateInt(env, externalErrCode);
        if (ANI_OK != (status = env->PromiseResolver_Resolve(resolver_, static_cast<ani_ref>(ret)))) {
            ANS_LOGD("PromiseResolver_Resolve faild. status %{public}d", status);
            return;
        }
    } else {
        ANS_LOGD("OnStsOperationCallback reject");
        std::string errMsg = FindAnsErrMsg(externalErrCode);
        ani_error rejection =
            static_cast<ani_error>(OHOS::NotificationSts::CreateError(env, externalErrCode, errMsg));
        if (ANI_OK != (status = env->PromiseResolver_Reject(resolver_, rejection))) {
            ANS_LOGD("PromiseResolver_Resolve faild. status %{public}d", status);
        }
    }
}

void StsDistributedOperationCallback::SetVm(ani_vm *vm)
{
    std::lock_guard<std::mutex> l(lock_);
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
    ANS_LOGD("done");
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
    ANS_LOGD("done");
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
    ANS_LOGD("done");
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
    ANS_LOGD("done");
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
    if (!SubscriberInstanceManager::GetInstance()->DelSubscriberInstancesInfo(etsEnv, ref_)) {
        ANS_LOGD("DelSubscriberInstancesInfo faild");
    } else {
        ANS_LOGD("DelSubscriberInstancesInfo suc..");
    }
    aniResult = vm_->DetachCurrentThread();
    if (aniResult != ANI_OK) {
        ANS_LOGD("DetachCurrentThread error. result: %{public}d.", aniResult);
        return;
    }
    ANS_LOGD("done");
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
    ANS_LOGD("done");
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
    ANS_LOGD("done");
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
    ANS_LOGD("done");
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
    ANS_LOGD("done");
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
    ANS_LOGD("done");
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
    ANS_LOGD("done");
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
    if (env == nullptr || obj == nullptr) {
        return false;
    }
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
    return (ref_ != nullptr && vm_ != nullptr);
}
bool StsSubscriberInstance::Compare(ani_env *env, ani_object obj)
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> l(lock_);
    if (!IsInit()) {
        return false;
    }
    if (obj == nullptr || env == nullptr) {
        return false;
    }
    ani_ref ref;
    if (env->GlobalReference_Create(obj, &ref) != ANI_OK) {
        return false;
    }
    ani_boolean result = ANI_FALSE;
    env->Reference_StrictEquals(ref, ref_, &result);
    env->GlobalReference_Delete(ref);
    return (result == ANI_TRUE) ? true : false;
}
bool StsSubscriberInstance::Compare(ani_env *env, ani_ref ref)
{
    ANS_LOGD("enter");
    if (!IsInit()) {
        return false;
    }
    if (ref == nullptr || env == nullptr) {
        return false;
    }
    ani_boolean result = ANI_FALSE;
    env->Reference_StrictEquals(ref, ref_, &result);
    return (result == ANI_TRUE) ? true : false;
}
bool StsSubscriberInstance::CallFunction(ani_env *env, const char *func, std::vector<ani_ref> &parm)
{
    ANS_LOGD("enter");
    if (env == nullptr) {
        return false;
    }
    ani_ref fn_ref;
    ani_status aniResult = env->Object_GetPropertyByName_Ref(static_cast<ani_object>(ref_), func, &fn_ref);
    if (ANI_OK != aniResult) {
        ANS_LOGD("Object_GetPropertyByName_Ref '%{public}s' error. result: %{public}d.", func, aniResult);
        return false;
    }
    ani_boolean IsUndefined = ANI_FALSE;
    if (ANI_OK != env->Reference_IsUndefined(fn_ref, &IsUndefined) || IsUndefined == ANI_TRUE) {
        ANS_LOGD("Reference_IsUndefined  faild. or IsUndefined");
        return false;
    }
    ani_ref fnReturnVal;
    aniResult = env->FunctionalObject_Call(
        static_cast<ani_fn_object>(fn_ref), parm.size(), parm.data(), &fnReturnVal);
    if (ANI_OK != aniResult) {
        ANS_LOGD("FunctionalObject_Call error. result: %{public}d.", aniResult);
        return false;
    }
    ANS_LOGD("done");
    return true;
}

bool SubscriberInstanceManager::HasNotificationSubscriber(
    ani_env *env, ani_object value, std::shared_ptr<StsSubscriberInstance> &subscriberInfo)
{
    ANS_LOGD("enter");
    std::lock_guard<std::mutex> lock(mutex_);
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
    ani_env *env, ani_ref ref)
{
    ANS_LOGD("enter");
    if (ref == nullptr) {
        ANS_LOGE("ref is null");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = subscriberInstances_.begin(); it != subscriberInstances_.end(); ++it) {
        if ((*it)->Compare(env, ref)) {
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
    if (subscriber == nullptr) {
        return false;
    }
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
    bool isSubscribeUndefine = IsUndefine(env, subscriber);
    bool isInfoUndefine = IsUndefine(env, info);
    if (isSubscribeUndefine) {
        ANS_LOGD("subscriber is undefine");
        OHOS::NotificationSts::ThrowError(env, ERROR_PARAM_INVALID, "subscriber is undefine");
        return false;
    }
    sptr<OHOS::Notification::NotificationSubscribeInfo> SubscribeInfo =
        new (std::nothrow) OHOS::Notification::NotificationSubscribeInfo();
    if (SubscribeInfo == nullptr) {
        return false;
    }
    if (!isInfoUndefine) {
        if (!UnwarpNotificationSubscribeInfo(env, info, *SubscribeInfo)) {
            ANS_LOGD("UnwarpNotificationSubscribeInfo faild");
            OHOS::NotificationSts::ThrowError(env, ERROR_PARAM_INVALID, "UnwarpNotificationSubscribeInfo faild");
            return false;
        }
    }
    std::shared_ptr<StsSubscriberInstance> stsSubscriber = nullptr;
    if (!HasNotificationSubscriber(env, subscriber, stsSubscriber)) {
        if (!GetNotificationSubscriber(env, subscriber, stsSubscriber)) {
            ANS_LOGD("GetNotificationSubscriber faild");
            OHOS::NotificationSts::ThrowError(env, ERROR_INTERNAL_ERROR, "GetNotificationSubscriber faild");
            return false;
        }
        if (!AddSubscriberInstancesInfo(env, stsSubscriber)) {
            ANS_LOGD("AddSubscriberInstancesInfo faild");
            OHOS::NotificationSts::ThrowError(env, ERROR_INTERNAL_ERROR, "GetNotificationSubscriber faild");
            return false;
        }
    }
    ErrCode status = ERR_OK;
    if (!isInfoUndefine) {
        status = NotificationHelper::SubscribeNotification(stsSubscriber, SubscribeInfo);
    } else {
        status = NotificationHelper::SubscribeNotification(stsSubscriber);
    }
    if (status != ERR_OK) {
        int32_t externalErrorCode = GetExternalCode(status);
        externalErrorCode = (externalErrorCode == ERR_OK) ? status : externalErrorCode;
        ANS_LOGD("SubscribeNotification faild. status %{public}d ErrorToExternal %{public}d",
            status, externalErrorCode);
        std::string msg = OHOS::NotificationSts::FindAnsErrMsg(externalErrorCode);
        OHOS::NotificationSts::ThrowError(env, externalErrorCode, msg);
        return false;
    }
    return true;
}

bool SubscriberInstanceManager::UnSubscribe(ani_env *env, ani_object subscriber)
{
    ANS_LOGD("enter");
    if (IsUndefine(env, subscriber)) {
        ANS_LOGD("Subscriber is undefine");
        std::string msg = OHOS::NotificationSts::FindAnsErrMsg(ERROR_PARAM_INVALID);
        OHOS::NotificationSts::ThrowError(env, ERROR_PARAM_INVALID, msg);
        return false;
    }
    std::shared_ptr<StsSubscriberInstance> stsSubscriber = nullptr;
    if (!HasNotificationSubscriber(env, subscriber, stsSubscriber)) {
        ANS_LOGD("Subscriber not found");
        std::string msg = OHOS::NotificationSts::FindAnsErrMsg(ERROR_PARAM_INVALID);
        OHOS::NotificationSts::ThrowError(env, ERROR_PARAM_INVALID, msg);
        return false;
    }
    bool ret = AddDeletingSubscriber(stsSubscriber);
    if (ret) {
        int32_t status = NotificationHelper::UnSubscribeNotification(stsSubscriber);
        if (status != ERR_OK) {
            int32_t externalErrorCode = GetExternalCode(status);
            externalErrorCode = (externalErrorCode == ERR_OK) ? status : externalErrorCode;
            ANS_LOGD("UnSubscribe faild. status %{public}d ErrorToExternal %{public}d",
                status, externalErrorCode);
            std::string msg = OHOS::NotificationSts::FindAnsErrMsg(externalErrorCode);
            OHOS::NotificationSts::ThrowError(env, externalErrorCode, msg);
            DelDeletingSubscriber(stsSubscriber);
        }
    } else {
        OHOS::NotificationSts::ThrowError(env, ERROR_INTERNAL_ERROR, "Subscriber is deleting");
        return false;
    }
    return true;
}

bool SubscriberInstanceManager::SubscribeSelf(ani_env *env, ani_object subscriber)
{
    ANS_LOGD("enter");
    bool isSubscribeUndefine = IsUndefine(env, subscriber);
    if (isSubscribeUndefine) {
        ANS_LOGD("subscriber is undefine");
        OHOS::NotificationSts::ThrowError(env, ERROR_PARAM_INVALID, "subscriber is undefine");
        return false;
    }
    std::shared_ptr<StsSubscriberInstance> stsSubscriber = nullptr;
    if (!HasNotificationSubscriber(env, subscriber, stsSubscriber)) {
        if (!GetNotificationSubscriber(env, subscriber, stsSubscriber)) {
            ANS_LOGD("GetNotificationSubscriber faild");
            OHOS::NotificationSts::ThrowError(env, ERROR_INTERNAL_ERROR, "GetNotificationSubscriber faild");
            return false;
        }
        if (!AddSubscriberInstancesInfo(env, stsSubscriber)) {
            ANS_LOGD("AddSubscriberInstancesInfo faild");
            OHOS::NotificationSts::ThrowError(env, ERROR_INTERNAL_ERROR, "GetNotificationSubscriber faild");
            return false;
        }
    }
    ErrCode status = ERR_OK;
    status = NotificationHelper::SubscribeNotificationSelf(stsSubscriber);
    if (status != ERR_OK) {
        int32_t externalErrorCode = GetExternalCode(status);
        externalErrorCode = (externalErrorCode == ERR_OK) ? status : externalErrorCode;
        ANS_LOGD("SubscribeNotificationSelf faild. status %{public}d ErrorToExternal %{public}d",
            status, externalErrorCode);
        std::string msg = OHOS::NotificationSts::FindAnsErrMsg(externalErrorCode);
        OHOS::NotificationSts::ThrowError(env, externalErrorCode, msg);
        return false;
    }
    return true;
}

bool GetDoubleValueByClassName(
    ani_env *env, ani_object param, const char *className, const char *name, ani_double &value)
{
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANS_LOGD("FindClass faild. %{public}s", className);
        return false;
    }
    ani_method idGetter;
    if (ANI_OK != env->Class_FindMethod(cls, name, nullptr, &idGetter)) {
        ANS_LOGD("Class_FindMethod faild. %{public}s", className);
        return false;
    }
    if (ANI_OK != env->Object_CallMethod_Double(param, idGetter, &value)) {
        ANS_LOGD("Object_CallMethod_Double faild. %{public}s", className);
        return false;
    }
    return true;
}

bool GetIntValueByClassName(
    ani_env *env, ani_object param, const char *className, const char *name, ani_int &value)
{
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANS_LOGD("FindClass faild. %{public}s", className);
        return false;
    }
    ani_method idGetter;
    if (ANI_OK != env->Class_FindMethod(cls, name, nullptr, &idGetter)) {
        ANS_LOGD("Class_FindMethod faild. %{public}s", className);
        return false;
    }
    if (ANI_OK != env->Object_CallMethod_Int(param, idGetter, &value)) {
        ANS_LOGD("Object_CallMethod_Int faild. %{public}s", className);
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
    ani_int idInt = 0;
    if (!GetIntValueByClassName(env, obj,
        "@ohos.notificationSubscribe.notificationSubscribe.NotificationKeyInner",
        Builder::BuildGetterName("id").c_str(), idInt)) {
        ANS_LOGD("GetIntValueByClassName id fail");
        return false;
    }
    OutObj.id = static_cast<int32_t>(idInt);
    std::string label;
    if (GetPropertyString(env, obj, "label", isUndefined, label) != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGD("UnWarpNotificationKey GetPropertyString label fail");
        return false;
    }
    OutObj.label = GetResizeStr(label, STR_MAX_SIZE);
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
    outObj.SetActionName(GetResizeStr(actionName, STR_MAX_SIZE));
    if (GetPropertyString(env, obj, "userInput", isUndefined, userInput) != ANI_OK || isUndefined == ANI_TRUE) {
        ANS_LOGD("ConvertOperationInfoToNative GetStringOrUndefined userInput fail");
        return false;
    }
    outObj.SetUserInput(GetResizeStr(userInput, LONG_STR_MAX_SIZE));
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
