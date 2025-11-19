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
#include <future>
#include <chrono>
#include "napi_badge_query_callback.h"
#include "common.h"
#include "ans_log_wrapper.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "nlohmann/json.hpp"
#include "napi_common_util.h"
#include "ans_log_wrapper.h"
#include "ans_inner_errors.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace NotificationNapi {
namespace {
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
constexpr int32_t INVALID_BADGE_NUMBER = -1;
constexpr int32_t BADGEQUERY_TIMEOUT_MS = 500;
} // namespace

static ffrt::mutex badgeQueryCallbackInfoMutex_;
static std::map<int32_t, std::shared_ptr<JSBadgeQueryCallBack>> badgeQueryCallbackInfos_;

struct NotificationBadgeQueryDataWorker {
    NotificationBundleOption bundle;
    int32_t userId;
    std::promise<int32_t> promise;
    std::weak_ptr<JSBadgeQueryCallBack> badgeQueryCallback;
};

struct AsyncCallbackBadgeNumberQuery {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    std::shared_ptr<JSBadgeQueryCallBack> objectInfo;
};

struct AsyncCallbackOffBadgeNumberQuery {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    int32_t userId;
    std::shared_ptr<JSBadgeQueryCallBack> objectInfo;
};

void ThreadFinished(napi_env env, void* data, [[maybe_unused]] void* context)
{
    ANS_LOGD("called");
}

int32_t ConvertBadgeNumberResult(napi_env env, napi_value funcResult)
{
    if (funcResult == nullptr) {
        ANS_LOGE("null funcResult");
        return INVALID_BADGE_NUMBER;
    }
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, funcResult, &valueType), false);
    if (valueType != napi_number) {
        ANS_LOGE("The funcResult is not napi_number.");
        return INVALID_BADGE_NUMBER;
    }
    int32_t number = INVALID_BADGE_NUMBER;
    if (!OHOS::AbilityRuntime::ConvertFromJsValue(env, funcResult, number)) {
        ANS_LOGE("Parse badge number failed.");
        return INVALID_BADGE_NUMBER;
    }
    ANS_LOGD("ConvertBadgeNumberResult num = %{public}d", number);
    return number;
}

napi_value BadgeNumberPromiseCallback(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    if (info == nullptr) {
        ANS_LOGE("null info");
        return nullptr;
    }

    size_t argc = ARGC_ONE;
    napi_value argv[ARGC_ONE] = {nullptr};
    void *data;

    napi_get_cb_info(env, info, &argc, &argv[0], nullptr, &data);
    int32_t number = ConvertBadgeNumberResult(env, argv[0]);

    auto *dataWorker = reinterpret_cast<NotificationBadgeQueryDataWorker *>(data);
    if (dataWorker == nullptr) {
        ANS_LOGW("NotificationBadgeQueryDataWorker is nullptr");
        return nullptr;
    }
    dataWorker->promise.set_value(number);
    delete dataWorker;
    dataWorker = nullptr;
    ANS_LOGD("Clean dataWorker");
    return nullptr;
}

bool HandleBadgeNumberPromise(napi_env env, napi_value funcResult, NotificationBadgeQueryDataWorker *dataWorker)
{
    napi_value promiseThen = nullptr;
    napi_get_named_property(env, funcResult, "then", &promiseThen);

    bool isCallable = false;
    napi_is_callable(env, promiseThen, &isCallable);
    if (!isCallable) {
        ANS_LOGE("HandleBadgeNumberPromise property then is not callable.");
        return false;
    }

    napi_value badgeNumberPromiseCallback;
    napi_create_function(env, "badgeNumberPromiseCallback", strlen("badgeNumberPromiseCallback"),
        BadgeNumberPromiseCallback, dataWorker, &badgeNumberPromiseCallback);

    napi_status status;
    napi_value argvPromise[ARGC_TWO] = { badgeNumberPromiseCallback, badgeNumberPromiseCallback };

    napi_value thenResult;
    status = napi_call_function(env, funcResult, promiseThen, ARGC_TWO, argvPromise, nullptr);
    if (status != napi_ok) {
        ANS_LOGE("Invoke badge query promise then error.");
        return false;
    }
    return true;
}

bool ThreadSafeBadgeQueryHandle(napi_env env, NotificationBadgeQueryDataWorker* dataWorker)
{
    ANS_LOGD("ThreadSafeBadgeQuery called");
    AbilityRuntime::HandleEscape handleEscape(env);
    napi_value result = nullptr;
    napi_handle_scope scope;
    auto status = napi_open_handle_scope(env, &scope);
    if (status != napi_ok || scope == nullptr) {
        ANS_LOGE("status: %{public}d", status);
        return false;
    }
    napi_create_object(env, &result);
    if (!Common::SetBundleOption(env, dataWorker->bundle, result)) {
        result = NotificationNapi::Common::NapiGetNull(env);
    }

    napi_value callback = nullptr;
    napi_value resultOut = nullptr;
    auto badgeQueryCallback = dataWorker->badgeQueryCallback.lock();
    if (badgeQueryCallback == nullptr) {
        ANS_LOGE("badgeQueryCallback is nullptr.");
        return false;
    }
    napi_get_reference_value(env, badgeQueryCallback->ref, &callback);
    if (callback == nullptr) {
        ANS_LOGE("callback is nullptr.");
        return false;
    }
    napi_status napi_result = napi_call_function(env, nullptr, callback, ARGS_ONE, &result, &resultOut);
    if (napi_result != napi_ok) {
        ANS_LOGE("napi_call_function failed, result = %{public}d", napi_result);
        return false;
    }
    napi_value funcResult = handleEscape.Escape(resultOut);
    bool isPromise = false;
    napi_is_promise(env, funcResult, &isPromise);
    if (!isPromise) {
        ANS_LOGE("Get badge number func is not promise.");
        return false;
    }
    if (!HandleBadgeNumberPromise(env, funcResult, dataWorker)) {
        ANS_LOGE("HandleBadgeNumberPromise failed");
        return false;
    }
    napi_close_handle_scope(env, scope);
    return true;
}

void ThreadSafeBadgeQuery(napi_env env, napi_value jsCallback, void* context, void* data)
{
    auto dataWorker = reinterpret_cast<NotificationBadgeQueryDataWorker *>(data);
    if (dataWorker == nullptr) {
        ANS_LOGE("null dataWorker");
        return;
    }
    if (!ThreadSafeBadgeQueryHandle(env, dataWorker)) {
        dataWorker->promise.set_value(INVALID_BADGE_NUMBER);
        delete dataWorker;
        dataWorker = nullptr;
        ANS_LOGD("Clean dataWorker");
    }
    return;
}

bool HasBadgeQueryCallBackInfo(const napi_env &env, const napi_value &value, const int32_t &userId,
    std::shared_ptr<JSBadgeQueryCallBack> &badgeQueryCallbackInfo)
{
    std::lock_guard<ffrt::mutex> lock(badgeQueryCallbackInfoMutex_);
    auto it = badgeQueryCallbackInfos_.find(userId);
    if (it == badgeQueryCallbackInfos_.end()) {
        return false;
    }
    napi_value callback = nullptr;
    napi_get_reference_value(env, it->second->ref, &callback);
    if (value == nullptr || callback == nullptr) {
        return false;
    }
    bool isEquals = false;
    napi_strict_equals(env, value, callback, &isEquals);
    if (isEquals) {
        ANS_LOGD("Same callback ref");
        badgeQueryCallbackInfo = it->second;
        return true;
    }
    return false;
}

napi_value GetBadgeQueryCallBackInfo(const napi_env &env, const napi_value &value,
    std::shared_ptr<JSBadgeQueryCallBack> &badgeQueryCallbackInfo)
{
    ANS_LOGD("GetBadgeQueryCallBackInfo called");
    badgeQueryCallbackInfo = std::make_shared<JSBadgeQueryCallBack>();
    if (badgeQueryCallbackInfo == nullptr) {
        ANS_LOGE("null callback");
        std::string msg = "Mandatory parameters are left unspecified. JSBadgeQueryCallBack is null";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }
    napi_create_reference(env, value, 1, &(badgeQueryCallbackInfo->ref));
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "tsfn", NAPI_AUTO_LENGTH, &resourceName);
    napi_threadsafe_function tsfn = nullptr;
    napi_create_threadsafe_function(env, nullptr, nullptr, resourceName, 0, 1, badgeQueryCallbackInfo->ref,
        ThreadFinished, nullptr, ThreadSafeBadgeQuery, &tsfn);
    badgeQueryCallbackInfo->SetThreadSafeFunction(tsfn);
    badgeQueryCallbackInfo->SetEnv(env);
    return Common::NapiGetNull(env);
}

bool AddBadgeQueryCallBackInfo(const napi_env &env, const int32_t &userId,
    const std::shared_ptr<JSBadgeQueryCallBack> &badgeQueryCallbackInfo)
{
    ANS_LOGD("AddBadgeQueryCallBackInfo called");
    if (badgeQueryCallbackInfo->ref == nullptr) {
        ANS_LOGE("null ref");
        return false;
    }
    std::lock_guard<ffrt::mutex> lock(badgeQueryCallbackInfoMutex_);
    badgeQueryCallbackInfos_.insert_or_assign(userId, badgeQueryCallbackInfo);

    return true;
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info,
    std::shared_ptr<JSBadgeQueryCallBack> &objectInfo, const int32_t &userId)
{
    ANS_LOGD("ParseParameters JSBadgeQueryCallBack");
    size_t argc = ARGC_ONE;
    napi_value argv[ARGC_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, NULL));
    if (argc != ARGC_ONE) {
        ANS_LOGE("Wrong number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;

    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_function) {
        ANS_LOGE("Wrong argument type for arg0. BadgeNumberCallback object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be BadgeNumberCallback.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    if (!HasBadgeQueryCallBackInfo(env, argv[PARAM0], userId, objectInfo)) {
        if (GetBadgeQueryCallBackInfo(env, argv[PARAM0], objectInfo) == nullptr) {
            ANS_LOGE("BadgeQueryCallBackInfo parse failed");
            return nullptr;
        }
        if (!AddBadgeQueryCallBackInfo(env, userId, objectInfo)) {
            ANS_LOGE("Add badgeQuery callbackInfo failed");
            return nullptr;
        }
    }

    return Common::NapiGetNull(env);
}

void ClearEnvCallback(void *data)
{
    ANS_LOGD("Env expired, need to clear env");
    JSBadgeQueryCallBack *badgeQueryCallBack = reinterpret_cast<JSBadgeQueryCallBack *>(data);
    if (badgeQueryCallBack == nullptr) {
        return;
    }
    badgeQueryCallBack->ClearEnv();
}

void AsyncCompleteCallbackNapiBadgeNumberQuery(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("AsyncCompleteCallbackNapiOnBadgeNumberQuery");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    AsyncCallbackBadgeNumberQuery *asynccallbackinfo = static_cast<AsyncCallbackBadgeNumberQuery*>(data);
    if (asynccallbackinfo == nullptr) {
        ANS_LOGE("null asynccallbackinfo");
        return;
    }
    Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
    napi_delete_async_work(env, asynccallbackinfo->asyncWork);
    delete asynccallbackinfo;
    asynccallbackinfo = nullptr;
    return;
}

napi_value NapiOnBadgeNumberQuery(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    std::shared_ptr<JSBadgeQueryCallBack> objectInfo;
    int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid < 0) {
        ANS_LOGE("uid is invalid");
        return Common::NapiGetUndefined(env);
    }
    int32_t userId = -1;
    if (Common::GetOsAccountLocalIdFromUid(uid, userId) != ERR_OK) {
        return Common::NapiGetUndefined(env);
    }
    if (ParseParameters(env, info, objectInfo, userId) == nullptr) {
        ANS_LOGD("ParseParameters failed");
        return Common::NapiGetUndefined(env);
    }

    if (objectInfo == nullptr) {
        ANS_LOGE("null objectInfo");
        return Common::NapiGetUndefined(env);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackBadgeNumberQuery {
        .env = env, .asyncWork = nullptr, .objectInfo = objectInfo};
    if (!asynccallbackinfo) {
        ANS_LOGD("null asynccallbackinfo");
        return Common::JSParaError(env, nullptr);
    }

    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "OnBadgeNumberQuery", NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiOnBadgeNumberQuery word excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackBadgeNumberQuery *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode = NotificationHelper::RegisterBadgeQueryCallback(
                    asynccallbackinfo->objectInfo);
            }
        },
        AsyncCompleteCallbackNapiBadgeNumberQuery,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_add_env_cleanup_hook(env, ClearEnvCallback, objectInfo.get());
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}

void AsyncCompleteCallbackNapiOffBadgeNumberQuery(napi_env env, napi_status status, void *data)
{
    ANS_LOGD("NapiOffBadgeNumberQuery work complete.");
    if (!data) {
        ANS_LOGE("Invalid async callback data");
        return;
    }
    auto asynccallbackinfo = static_cast<AsyncCallbackOffBadgeNumberQuery *>(data);
    if (asynccallbackinfo == nullptr) {
        ANS_LOGE("null asynccallbackinfo");
        return;
    }
    
    if (asynccallbackinfo->objectInfo) {
        napi_threadsafe_function tsfn = asynccallbackinfo->objectInfo->GetThreadSafeFunction();
        if (tsfn != nullptr) {
            napi_release_threadsafe_function(tsfn, napi_tsfn_release);
            asynccallbackinfo->objectInfo->SetThreadSafeFunction(nullptr);
        }
        if (asynccallbackinfo->objectInfo->ref != nullptr) {
            napi_delete_reference(env, asynccallbackinfo->objectInfo->ref);
            asynccallbackinfo->objectInfo->ref = nullptr;
        }
        asynccallbackinfo->objectInfo->SetEnv(nullptr);
    }

    Common::CreateReturnValue(env, asynccallbackinfo->info, Common::NapiGetNull(env));
    napi_delete_async_work(env, asynccallbackinfo->asyncWork);
    delete asynccallbackinfo;
    asynccallbackinfo = nullptr;
    return;
}

napi_value NapiOffBadgeNumberQuery(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");
    int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid < 0) {
        ANS_LOGE("uid is invalid");
        return Common::NapiGetUndefined(env);
    }
    int32_t userId = -1;
    if (Common::GetOsAccountLocalIdFromUid(uid, userId) != ERR_OK) {
        return Common::NapiGetUndefined(env);
    }
    std::shared_ptr<JSBadgeQueryCallBack> callback;
    {
        std::lock_guard<ffrt::mutex> lock(badgeQueryCallbackInfoMutex_);
        auto it = badgeQueryCallbackInfos_.find(userId);
        if (it == badgeQueryCallbackInfos_.end()) {
            ANS_LOGE("Never registered.");
            return Common::NapiGetUndefined(env);
        }
        callback = it->second;
        badgeQueryCallbackInfos_.erase(userId);
    }

    auto asynccallbackinfo = new (std::nothrow) AsyncCallbackOffBadgeNumberQuery {
        .env = env, .asyncWork = nullptr, .userId = userId, .objectInfo = callback};
    if (!asynccallbackinfo) {
        ANS_LOGD("null asynccallbackinfo");
        return Common::JSParaError(env, nullptr);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, nullptr, asynccallbackinfo->info, promise);
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "OffBadgeNumberQuery", NAPI_AUTO_LENGTH, &resourceName);

    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("NapiOffBadgeNumberQuery word excute.");
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackOffBadgeNumberQuery *>(data);
            if (asynccallbackinfo) {
                asynccallbackinfo->info.errorCode =
                    NotificationHelper::UnRegisterBadgeQueryCallback(asynccallbackinfo->objectInfo);
            }
        },
        AsyncCompleteCallbackNapiOffBadgeNumberQuery,
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);
    return promise;
}

JSBadgeQueryCallBack::JSBadgeQueryCallBack() {}

JSBadgeQueryCallBack::~JSBadgeQueryCallBack() {}

void JSBadgeQueryCallBack::SetThreadSafeFunction(const napi_threadsafe_function &tsfn)
{
    std::lock_guard<ffrt::mutex> lock(tsfnMutex_);
    tsfn_ = tsfn;
}

napi_threadsafe_function JSBadgeQueryCallBack::GetThreadSafeFunction()
{
    std::lock_guard<ffrt::mutex> lock(tsfnMutex_);
    return tsfn_;
}

void JSBadgeQueryCallBack::SetEnv(const napi_env &env)
{
    env_ = env;
}

void JSBadgeQueryCallBack::ClearEnv()
{
    {
        std::lock_guard<ffrt::mutex> lock(tsfnMutex_);
        if (tsfn_ != nullptr) {
            napi_release_threadsafe_function(tsfn_, napi_tsfn_release);
            tsfn_ = nullptr;
        }
    }
    if (ref != nullptr) {
        napi_delete_reference(env_, ref);
        ref = nullptr;
    }
    if (env_ != nullptr) {
        napi_remove_env_cleanup_hook(env_, ClearEnvCallback, this);
        env_ = nullptr;
    }
}

ErrCode JSBadgeQueryCallBack::OnBadgeNumberQuery(const sptr<NotificationBundleOption>& bundleOption,
    int32_t &badgeNumber)
{
    if (ref == nullptr) {
        ANS_LOGE("null badgeQueryCallBack ref");
        return ERR_INVALID_DATA;
    }
    if (bundleOption == nullptr) {
        ANS_LOGE("null bundleOption");
        return ERR_INVALID_DATA;
    }

    NotificationBadgeQueryDataWorker* dataWorker = new (std::nothrow) NotificationBadgeQueryDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("null dataWorker");
        return ERR_INVALID_DATA;
    }

    dataWorker->bundle.SetBundleName(bundleOption->GetBundleName());
    dataWorker->bundle.SetUid(bundleOption->GetUid());
    dataWorker->badgeQueryCallback = std::static_pointer_cast<JSBadgeQueryCallBack>(shared_from_this());
    auto future = dataWorker->promise.get_future();
    {
        std::lock_guard<ffrt::mutex> lock(tsfnMutex_);
        if (tsfn_ == nullptr) {
            ANS_LOGD("null tsfn_");
            delete dataWorker;
            dataWorker = nullptr;
            return ERR_INVALID_DATA;
        }
        napi_acquire_threadsafe_function(tsfn_);
        napi_call_threadsafe_function(tsfn_, (void*)dataWorker, napi_tsfn_nonblocking);
        napi_release_threadsafe_function(tsfn_, napi_tsfn_release);
    }
    if (future.wait_for(std::chrono::milliseconds(BADGEQUERY_TIMEOUT_MS)) != std::future_status::ready) {
        ANS_LOGE("Badge query timeout after 500 ms.");
        badgeNumber = INVALID_BADGE_NUMBER;
        return ERR_OK;
    }
    badgeNumber = future.get();
    return ERR_OK;
}
} // namespace Notification
} // namespace OHOS
