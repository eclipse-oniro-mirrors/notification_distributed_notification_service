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
#include "sts_badge_query_callback.h"

#include <future>
#include <chrono>
#include "ani_display_badge.h"
#include "ans_log_wrapper.h"
#include "sts_bundle_option.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "notification_helper.h"
#include "notification_bundle_option.h"
#include "sts_convert_other.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace NotificationSts {
constexpr int32_t INVALID_BADGE_NUMBER = -1;
constexpr int32_t BADGEQUERY_TIMEOUT_MS = 500;
constexpr int32_t INVALID_USER_ID = -1;

ffrt::mutex BadgeNumberPromiseManager::promiseMutex_;
std::unordered_map<int32_t, std::shared_ptr<std::promise<int32_t>>> BadgeNumberPromiseManager::promises_;

std::future<int32_t> BadgeNumberPromiseManager::CreatePromise(int32_t uid)
{
    std::lock_guard<ffrt::mutex> lock(promiseMutex_);
    auto promise = std::make_shared<std::promise<int32_t>>();
    std::future<int32_t> future = promise->get_future();
    promises_[uid] = promise;
    return future;
}

void BadgeNumberPromiseManager::SetValue(int32_t uid, int32_t value)
{
    std::lock_guard<ffrt::mutex> lock(promiseMutex_);
    auto it = promises_.find(uid);
    if (it != promises_.end()) {
        it->second->set_value(value);
        promises_.erase(it);
    } else {
        ANS_LOGW("No promise found for uid %{public}d", uid);
    }
    return;
}

void BadgeNumberPromiseManager::RemovePromise(int32_t uid)
{
    std::lock_guard<ffrt::mutex> lock(promiseMutex_);
    promises_.erase(uid);
}

bool StsBadgeQueryCallBack::IsInit()
{
    ANS_LOGD("enter");
    return (ref_ != nullptr && vm_ != nullptr);
}

bool StsBadgeQueryCallBack::SetObject(ani_env *env, ani_object obj)
{
    std::lock_guard<ffrt::mutex> lock(callbackMutex_);
    if (env == nullptr || obj == nullptr) {
        return false;
    }
    if (env->GetVM(&vm_) != ANI_OK) {
        ANS_LOGW("GetVM faild");
        return false;
    }
    if (env->GlobalReference_Create(obj, &ref_) != ANI_OK) {
        ANS_LOGW("GlobalReference_Create faild");
        return false;
    }
    return true;
}

void StsBadgeQueryCallBack::Clean(ani_env *env)
{
    std::lock_guard<ffrt::mutex> lock(callbackMutex_);
    if (env == nullptr) {
        return;
    }
    if (env->GlobalReference_Delete(ref_) != ANI_OK) {
        ANS_LOGW("GlobalReference_Delete faild");
        return;
    }
    ref_ = nullptr;
    ANS_LOGD("Clean succ");
    return;
}

void StsBadgeQueryCallBack::HandleBadgeQueryCallback(ani_env *env, std::vector<ani_ref> &param)
{
    ANS_LOGD("enter");
    if (env == nullptr) {
        ANS_LOGE("env is nullptr");
        return;
    }

    ani_boolean IsUndefined = ANI_FALSE;
    if (env->Reference_IsUndefined(ref_, &IsUndefined) != ANI_OK || IsUndefined == ANI_TRUE) {
        ANS_LOGD("Reference_IsUndefined faild.");
        return;
    }
    ani_status status = ANI_OK;
    ani_ref funcResult;
    if (ANI_OK != (status = env->FunctionalObject_Call(static_cast<ani_fn_object>(ref_),
        param.size(), param.data(), &funcResult))) {
        ANS_LOGE("FunctionalObject_Call faild. status %{public}d", status);
        return;
    }

    ANS_LOGD("HandleBadgeQueryCallback done");
    return;
}

ErrCode StsBadgeQueryCallBack::GetBadgeNumberQueryInfo(const sptr<NotificationBundleOption> &bundleOption,
    int32_t &uid, std::shared_ptr<StsBadgeQueryCallBack> &callback)
{
    if (bundleOption == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_INVALID_DATA;
    }

    uid = bundleOption->GetUid();
    if (uid < 0) {
        ANS_LOGE("uid is invalid, %{public}d", uid);
        return ERR_INVALID_DATA;
    }
    int32_t userId = INVALID_USER_ID;
    if (GetOsAccountLocalIdFromUid(uid, userId) != ERR_OK) {
        return ERR_INVALID_DATA;
    }

    callback = StsBadgeQueryCallBackManager::GetInstance()->GetBadgeQueryCallbackInfo(userId);
    if (callback == nullptr) {
        ANS_LOGD("BadgeQueryCallback is nullptr");
        return ERR_INVALID_DATA;
    }
    return ERR_OK;
}

ErrCode StsBadgeQueryCallBack::OnBadgeNumberQuery(const sptr<NotificationBundleOption> &bundleOption,
    int32_t &badgeNumber)
{
    int32_t uid;
    std::shared_ptr<StsBadgeQueryCallBack> callback;
    if (GetBadgeNumberQueryInfo(bundleOption, uid, callback) != ERR_OK) {
        return ERR_INVALID_DATA;
    }

    std::future<int32_t> future = BadgeNumberPromiseManager::CreatePromise(uid);
    {
        std::lock_guard<ffrt::mutex> lock(callbackMutex_);
        ani_env* etsEnv;
        ani_status aniResult = ANI_ERROR;
        ani_options aniArgs { 0, nullptr };
        aniResult = vm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &etsEnv);
        if (aniResult != ANI_OK) {
            ANS_LOGD("AttachCurrentThread error. result: %{public}d.", aniResult);
            BadgeNumberPromiseManager::RemovePromise(uid);
            return ERR_INVALID_DATA;
        }
        ani_object bundleObj;
        if (!WrapBundleOption(etsEnv, bundleOption, bundleObj) || bundleObj == nullptr) {
            BadgeNumberPromiseManager::RemovePromise(uid);
            return ERR_INVALID_DATA;
        }
        std::vector<ani_ref> param;
        param.push_back(bundleObj);
        callback->HandleBadgeQueryCallback(etsEnv, param);
        aniResult = vm_->DetachCurrentThread();
        if (aniResult != ANI_OK) {
            ANS_LOGD("DetachCurrentThread error. result: %{public}d.", aniResult);
            BadgeNumberPromiseManager::RemovePromise(uid);
            return ERR_INVALID_DATA;
        }
    }
    if (future.wait_for(std::chrono::milliseconds(BADGEQUERY_TIMEOUT_MS)) != std::future_status::ready) {
        ANS_LOGE("Badge query timeout after 500 ms.");
        badgeNumber = INVALID_BADGE_NUMBER;
        BadgeNumberPromiseManager::RemovePromise(uid);
        return ERR_OK;
    }
    badgeNumber = future.get();
    ANS_LOGD("Bundle(%{public}s_%{public}d) get badgeNumber = %{public}d",
        bundleOption->GetBundleName().c_str(), uid, badgeNumber);
    return ERR_OK;
}

std::shared_ptr<StsBadgeQueryCallBack> StsBadgeQueryCallBackManager::GetBadgeQueryCallbackInfo(int32_t userId)
{
    std::lock_guard<ffrt::mutex> lock(badgeQueryCallbackInfoMutex_);
    auto it = badgeQueryCallbackInfos_.find(userId);
    if (it == badgeQueryCallbackInfos_.end()) {
        return nullptr;
    }
    return badgeQueryCallbackInfos_[userId];
}

bool StsBadgeQueryCallBackManager::MakeBadgeQueryCallBackInfo(ani_env *env, ani_fn_object value,
    std::shared_ptr<StsBadgeQueryCallBack> &badgeQueryCallback)
{
    ANS_LOGD("enter");
    badgeQueryCallback = std::make_shared<StsBadgeQueryCallBack>();
    if (!badgeQueryCallback->SetObject(env, value)) {
        ANS_LOGD("SetObject faild");
        return false;
    }
    return true;
}


bool StsBadgeQueryCallBackManager::AddBadgeQueryCallBackInfo(int32_t userId,
    std::shared_ptr<StsBadgeQueryCallBack> &badgeQueryCallback)
{
    ANS_LOGD("enter");
    if (!badgeQueryCallback->IsInit()) {
        ANS_LOGE("badgeQueryCallback not init");
        return false;
    }
    std::lock_guard<ffrt::mutex> lock(badgeQueryCallbackInfoMutex_);
    badgeQueryCallbackInfos_.insert_or_assign(userId, badgeQueryCallback);
    return true;
}

void StsBadgeQueryCallBackManager::DelBadgeQueryCallBackInfo(int32_t userId)
{
    ANS_LOGD("enter");
    std::lock_guard<ffrt::mutex> lock(badgeQueryCallbackInfoMutex_);
    badgeQueryCallbackInfos_.erase(userId);
    return;
}

void StsBadgeQueryCallBackManager::AniOnBadgeNumberQuery(ani_env *env, ani_fn_object fn)
{
    ANS_LOGD("AniOnBadgeNumberQuery call");
    bool isFnUndefine = IsUndefine(env, fn);
    if (isFnUndefine) {
        ANS_LOGD("BadgeQueryCallback is undefine");
        OHOS::NotificationSts::ThrowError(env, ERROR_PARAM_INVALID, "BadgeQueryCallback is undefine");
        return;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid < 0) {
        ANS_LOGE("uid is invalid, %{public}d", uid);
        return;
    }
    int32_t userId = INVALID_USER_ID;
    if (GetOsAccountLocalIdFromUid(uid, userId) != ERR_OK) {
        return;
    }

    std::shared_ptr<StsBadgeQueryCallBack> objectInfo;
    if (!MakeBadgeQueryCallBackInfo(env, fn, objectInfo)) {
        ANS_LOGE("BadgeQueryCallBackInfo parse failed");
        return;
    }
    if (!AddBadgeQueryCallBackInfo(userId, objectInfo)) {
        ANS_LOGE("Add badgeQuery callbackInfo failed");
        return;
    }
    ErrCode status = ERR_OK;
    status = NotificationHelper::RegisterBadgeQueryCallback(objectInfo);
    if (status != ERR_OK) {
        int32_t externalErrorCode = GetExternalCode(status);
        externalErrorCode = (externalErrorCode == ERR_OK) ? status : externalErrorCode;
        ANS_LOGD("AniOnBadgeNumberQuery faild. UserId %{public}d status %{public}d ErrorToExternal %{public}d",
            userId, status, externalErrorCode);
        std::string msg = OHOS::NotificationSts::FindAnsErrMsg(externalErrorCode);
        OHOS::NotificationSts::ThrowError(env, externalErrorCode, msg);
        return;
    }
    ANS_LOGD("AniOnBadgeNumberQuery end");
    return;
}

void StsBadgeQueryCallBackManager::AniOffBadgeNumberQuery(ani_env *env)
{
    ANS_LOGD("AniOffBadgeNumberQuery call");
    int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid < 0) {
        ANS_LOGE("uid is invalid, %{public}d", uid);
        return;
    }
    int32_t userId = INVALID_USER_ID;
    if (GetOsAccountLocalIdFromUid(uid, userId) != ERR_OK) {
        return;
    }

    std::shared_ptr<StsBadgeQueryCallBack> callback =
        StsBadgeQueryCallBackManager::GetInstance()->GetBadgeQueryCallbackInfo(userId);
    if (callback == nullptr) {
        ANS_LOGE("UserId(%{public}d) badgeQueryCallback unregistered", userId);
        return;
    }

    ErrCode status = ERR_OK;
    status = NotificationHelper::UnRegisterBadgeQueryCallback(callback);
    if (status != ERR_OK) {
        int32_t externalErrorCode = GetExternalCode(status);
        externalErrorCode = (externalErrorCode == ERR_OK) ? status : externalErrorCode;
        ANS_LOGE("AniOnBadgeNumberQuery faild. UserId %{public}d status %{public}d ErrorToExternal %{public}d",
            userId, status, externalErrorCode);
        std::string msg = OHOS::NotificationSts::FindAnsErrMsg(externalErrorCode);
        OHOS::NotificationSts::ThrowError(env, externalErrorCode, msg);
    }
    callback->Clean(env);
    DelBadgeQueryCallBackInfo(userId);

    ANS_LOGD("AniOffBadgeNumberQuery end");
    return;
}

void StsBadgeQueryCallBackManager::AniHandleBadgeNumberPromise(ani_env *env, ani_object bundle, ani_long num)
{
    ANS_LOGD("enter");
    int32_t badgeNumber = static_cast<int32_t>(num);
    NotificationBundleOption bundleOption;
    if (UnwrapBundleOption(env, bundle, bundleOption) != true) {
        NotificationSts::ThrowErrorWithMsg(env, "UnwrapBundleOption ERROR_INTERNAL_ERROR");
        return;
    }
    int32_t uid = bundleOption.GetUid();
    if (uid < 0) {
        ANS_LOGE("uid is invalid, %{public}d", uid);
        return;
    }

    ANS_LOGD("Bundle(%{public}s_%{public}d) set future badgenumber %{public}d",
        bundleOption.GetBundleName().c_str(), bundleOption.GetUid(), badgeNumber);
    BadgeNumberPromiseManager::SetValue(uid, badgeNumber);
    ANS_LOGD("AniHandleBadgeNumberPromise end");
    return;
}
}
}
