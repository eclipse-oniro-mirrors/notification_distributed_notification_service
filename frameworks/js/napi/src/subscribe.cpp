/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "subscribe.h"
#include "ans_inner_errors.h"
#include <mutex>
#include <uv.h>
#include "hitrace_util.h"

namespace OHOS {
namespace NotificationNapi {
const int32_t SUBSRIBE_MAX_PARA = 3;
const int32_t NO_DELETE_REASON = -1;
const int32_t DISTRIBUTE_JUMP_PARA = 1;
const int32_t DISTRIBUTE_REPLY_PARA = 2;
const std::string CONSUME = "onConsume";
const std::string CANCEL = "onCancel";
const std::string UPDATE = "onUpdate";
const std::string CONNECTED = "onConnect";
const std::string DIS_CONNECTED = "onDisconnect";
const std::string DIE = "onDestroy";
const std::string DISTURB_MODE_CHANGE = "onDisturbModeChange";
const std::string DISTURB_DATE_CHANGE = "onDoNotDisturbDateChange";
const std::string DISTURB_CHANGED = "onDoNotDisturbChanged";
const std::string ENABLE_NOTIFICATION_CHANGED = "OnEnabledNotificationChanged";
const std::string BADGE_CHANGED = "OnBadgeChanged";
const std::string BADGE_ENABLED_CHANGED = "OnBadgeEnabledChanged";
const std::string BATCH_CANCEL = "onBatchCancel";

enum class Type {
    UNKNOWN,
    CANCEL,
    BATCH_CANCEL,
    CONSUME,
    UPDATE,
    CONNECTED,
    DIS_CONNECTED,
    DIE,
    DISTURB_DATE_CHANGE,
    DISTURB_CHANGED,
    ENABLE_NOTIFICATION_CHANGED,
    BADGE_CHANGED,
    BADGE_ENABLED_CHANGED
};

struct NotificationReceiveDataWorker {
    std::shared_ptr<OHOS::Notification::Notification> request;
    std::vector<std::shared_ptr<OHOS::Notification::Notification>> requestList;
    std::shared_ptr<NotificationSortingMap> sortingMap;
    NotificationDoNotDisturbDate date;
    EnabledNotificationCallbackData callbackData;
    BadgeNumberCallbackData badge;
    int32_t deleteReason = 0;
    int32_t result = 0;
    int32_t disturbMode = 0;
    std::weak_ptr<SubscriberInstance> subscriber;
    Type type;
};

napi_value SetSubscribeCallbackData(const napi_env &env,
    const std::shared_ptr<OHOS::Notification::Notification> &request,
    const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason, napi_value &result)
{
    ANS_LOGD("called");
    if (request == nullptr) {
        ANS_LOGE("null request");
        return Common::NapiGetBoolean(env, false);
    }

    if (sortingMap == nullptr) {
        ANS_LOGD("null sortingMap");
        return Common::NapiGetBoolean(env, false);
    }

    // request: NotificationRequest
    napi_value requestResult = nullptr;
    napi_create_object(env, &requestResult);
    if (!Common::SetNotification(env, request.get(), requestResult)) {
        ANS_LOGE("SetNotification call failed");
        return Common::NapiGetBoolean(env, false);
    }
    napi_set_named_property(env, result, "request", requestResult);

    // sortingMap?: NotificationSortingMap
    napi_value sortingMapResult = nullptr;
    napi_create_object(env, &sortingMapResult);
    if (!Common::SetNotificationSortingMap(env, sortingMap, sortingMapResult)) {
        ANS_LOGE("SetNotificationSortingMap call failed");
        return Common::NapiGetBoolean(env, false);
    }
    napi_set_named_property(env, result, "sortingMap", sortingMapResult);

    // reason?: number
    if (deleteReason != NO_DELETE_REASON) {
        napi_value value = nullptr;
        int32_t outReason = 0;
        if (!AnsEnumUtil::ReasonCToJS(deleteReason, outReason)) {
            return Common::NapiGetBoolean(env, false);
        }
        napi_create_int32(env, outReason, &value);
        napi_set_named_property(env, result, "reason", value);
    }

    // sound?: string
    napi_value soundResult = nullptr;
    std::string sound;
    if (request->EnableSound()) {
        sound = request->GetSound().ToString();
    }
    napi_create_string_utf8(env, sound.c_str(), NAPI_AUTO_LENGTH, &soundResult);
    napi_set_named_property(env, result, "sound", soundResult);

    // vibrationValues?: Array<number>
    napi_value arr = nullptr;
    napi_create_array(env, &arr);
    if (request->EnableVibrate()) {
        uint32_t count = 0;
        for (auto vec : request->GetVibrationStyle()) {
            napi_value nVibrationValue = nullptr;
            napi_create_int64(env, vec, &nVibrationValue);
            napi_set_element(env, arr, count, nVibrationValue);
            count++;
        }
    }
    napi_set_named_property(env, result, "vibrationValues", arr);

    return Common::NapiGetBoolean(env, true);
}

static void ClearEnvCallback(void *data)
{
    ANS_LOGD("Env expired, need to clear env");
    SubscriberInstance *subscriber = reinterpret_cast<SubscriberInstance *>(data);
    subscriber->ClearEnv();
}

SubscriberInstance::SubscriberInstance()
{}

SubscriberInstance::~SubscriberInstance()
{
    DeleteRef();
}

void SubscriberInstance::DeleteRef()
{
    {
        std::lock_guard<ffrt::mutex> lock(tsfnMutex_);
        if (tsfn_ != nullptr) {
            napi_release_threadsafe_function(tsfn_, napi_tsfn_release);
            tsfn_ = nullptr;
        }
    }
    if (canceCallbackInfo_.ref != nullptr) {
        napi_delete_reference(canceCallbackInfo_.env, canceCallbackInfo_.ref);
        canceCallbackInfo_.ref = nullptr;
    }
    if (consumeCallbackInfo_.ref != nullptr) {
        napi_delete_reference(consumeCallbackInfo_.env, consumeCallbackInfo_.ref);
        consumeCallbackInfo_.ref = nullptr;
    }
    if (updateCallbackInfo_.ref != nullptr) {
        napi_delete_reference(updateCallbackInfo_.env, updateCallbackInfo_.ref);
        updateCallbackInfo_.ref = nullptr;
    }
    if (subscribeCallbackInfo_.ref != nullptr) {
        napi_delete_reference(subscribeCallbackInfo_.env, subscribeCallbackInfo_.ref);
        subscribeCallbackInfo_.ref = nullptr;
    }
    if (unsubscribeCallbackInfo_.ref != nullptr) {
        napi_delete_reference(unsubscribeCallbackInfo_.env, unsubscribeCallbackInfo_.ref);
        unsubscribeCallbackInfo_.ref = nullptr;
    }
    if (dieCallbackInfo_.ref != nullptr) {
        napi_delete_reference(dieCallbackInfo_.env, dieCallbackInfo_.ref);
        dieCallbackInfo_.ref = nullptr;
    }
    if (disturbModeCallbackInfo_.ref != nullptr) {
        napi_delete_reference(disturbModeCallbackInfo_.env, disturbModeCallbackInfo_.ref);
        disturbModeCallbackInfo_.ref = nullptr;
    }
    if (enabledNotificationCallbackInfo_.ref != nullptr) {
        napi_delete_reference(enabledNotificationCallbackInfo_.env, enabledNotificationCallbackInfo_.ref);
        enabledNotificationCallbackInfo_.ref = nullptr;
    }
    if (batchCancelCallbackInfo_.ref != nullptr) {
        napi_delete_reference(batchCancelCallbackInfo_.env, batchCancelCallbackInfo_.ref);
        batchCancelCallbackInfo_.ref = nullptr;
    }
    if (env_ != nullptr) {
        napi_remove_env_cleanup_hook(env_, ClearEnvCallback, this);
    }
}

void SubscriberInstance::ClearEnv()
{
    DeleteRef();
    env_ = nullptr;
}

void SubscriberInstance::CallThreadSafeFunc(void* data)
{
    std::lock_guard<ffrt::mutex> lock(tsfnMutex_);
    if (tsfn_ == nullptr) {
        auto dataWorker = reinterpret_cast<NotificationReceiveDataWorker *>(data);
        delete dataWorker;
        dataWorker = nullptr;
        ANS_LOGD("null tsfn_");
        return;
    }
    napi_acquire_threadsafe_function(tsfn_);
    napi_call_threadsafe_function(tsfn_, data, napi_tsfn_nonblocking);
    napi_release_threadsafe_function(tsfn_, napi_tsfn_release);
    return;
}

void ThreadSafeOnCancel(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("called");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("null dataWorkerData");
        return;
    }
    auto subscriber = dataWorkerData->subscriber.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return;
    }
    napi_value result = nullptr;
    napi_handle_scope scope;
    auto status = napi_open_handle_scope(env, &scope);
    if (status != napi_ok || scope == nullptr) {
        ANS_LOGE("status: %{public}d", status);
        return;
    }
    napi_create_object(env, &result);
    if (!SetSubscribeCallbackData(env,
        dataWorkerData->request,
        dataWorkerData->sortingMap,
        dataWorkerData->deleteReason,
        result)) {
        ANS_LOGE("Failed to convert data to JS");
    } else {
        Common::SetCallback(env, subscriber->GetCallbackInfo(CANCEL).ref, result);
    }
    napi_close_handle_scope(env, scope);
}

void SubscriberInstance::OnCanceled(const std::shared_ptr<OHOS::Notification::Notification> &request,
    const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason)
{
    ANS_LOGD("called");

    if (canceCallbackInfo_.ref == nullptr || canceCallbackInfo_.env == nullptr) {
        ANS_LOGE("null ref or env");
        return;
    }

    if (request == nullptr) {
        ANS_LOGE("null request");
        return;
    }

    if (sortingMap == nullptr) {
        ANS_LOGE("null sortingMap");
        return;
    }
    ANS_LOGI("Key = %{public}s. sortingMap size = %{public}zu. deleteReason = %{public}d",
        request->GetKey().c_str(), sortingMap->GetKey().size(), deleteReason);
    ANS_LOGD("SubscriberInstance::OnCanceled instanceKey: %{public}s", request->GetInstanceKey().c_str());
    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("null dataWorker");
        return;
    }

    dataWorker->request = request;
    dataWorker->sortingMap = sortingMap;
    dataWorker->deleteReason = deleteReason;
    dataWorker->type = Type::CANCEL;
    dataWorker->subscriber = std::static_pointer_cast<SubscriberInstance>(shared_from_this());

    CallThreadSafeFunc(dataWorker);
}

void ThreadSafeOnBatchCancel(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("called");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("null dataWorkerData");
        return;
    }
    auto subscriber = dataWorkerData->subscriber.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return;
    }
    napi_value resultArray = nullptr;
    napi_handle_scope scope;
    auto status = napi_open_handle_scope(env, &scope);
    if (status != napi_ok || scope == nullptr) {
        ANS_LOGE("status: %{public}d", status);
        return;
    }
    napi_create_array(env, &resultArray);
    int index = 0;
    for (auto request : dataWorkerData->requestList) {
        napi_value result = nullptr;
        napi_create_object(env, &result);
        if (SetSubscribeCallbackData(env, request,
            dataWorkerData->sortingMap, dataWorkerData->deleteReason, result)) {
            napi_set_element(env, resultArray, index, result);
            index++;
        }
    }
    uint32_t elementCount = 0;
    napi_get_array_length(env, resultArray, &elementCount);
    ANS_LOGI("Notifications size: %{public}d ", elementCount);
    if (elementCount > 0) {
        Common::SetCallback(env, subscriber->GetCallbackInfo(BATCH_CANCEL).ref, resultArray);
    }

    napi_close_handle_scope(env, scope);
}

void SubscriberInstance::OnBatchCanceled(const std::vector<std::shared_ptr<OHOS::Notification::Notification>>
    &requestList, const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason)
{
    if (batchCancelCallbackInfo_.ref == nullptr || batchCancelCallbackInfo_.env == nullptr) {
        ANS_LOGE("null ref or env");
        return;
    }
    if (requestList.empty()) {
        ANS_LOGE("empty requestList");
        return;
    }
    if (sortingMap == nullptr) {
        ANS_LOGE("null sortingMap");
        return;
    }
    std::string notificationKeys = "";
    for (auto notification : requestList) {
        notificationKeys.append(notification->GetKey()).append("-");
    }
    ANS_LOGI("Reason = %{public}d, sortingMap size = %{public}zu, keys = %{public}s",
        deleteReason, sortingMap->GetKey().size(), notificationKeys.c_str());

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("null dataWorker");
        return;
    }
    dataWorker->requestList = requestList;
    dataWorker->sortingMap = sortingMap;
    dataWorker->deleteReason = deleteReason;
    dataWorker->type = Type::BATCH_CANCEL;
    dataWorker->subscriber = std::static_pointer_cast<SubscriberInstance>(shared_from_this());

    CallThreadSafeFunc(dataWorker);
    return;
}

bool SubscriberInstance::HasOnBatchCancelCallback()
{
    if (batchCancelCallbackInfo_.ref == nullptr) {
        ANS_LOGE("null ref");
        return false;
    }
    return true;
}

void ThreadSafeOnConsumed(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("called");
    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    auto additionalData = dataWorkerData->request->GetNotificationRequest().GetAdditionalData();
    if (additionalData && additionalData->HasParam("_oh_ans_sys_traceid")) {
        std::stringstream sin(additionalData->GetStringParam("_oh_ans_sys_traceid"));
        uint64_t chainId;
        if (sin >> std::hex >> chainId) {
            TraceChainUtil traceChainUtil = TraceChainUtil();
            OHOS::HiviewDFX::HiTraceId traceId = OHOS::HiviewDFX::HiTraceChain::GetId();
            traceId.SetChainId(chainId);
            OHOS::HiviewDFX::HiTraceChain::SetId(traceId);
        }
    }
    ANS_LOGD("called");
    if (dataWorkerData == nullptr) {
        ANS_LOGE("null dataWorkerData");
        return;
    }
    auto subscriber = dataWorkerData->subscriber.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return;
    }
    napi_value result = nullptr;
    napi_handle_scope scope;
    auto status = napi_open_handle_scope(env, &scope);
    if (status != napi_ok || scope == nullptr) {
        ANS_LOGE("status: %{public}d", status);
        return;
    }
    napi_create_object(env, &result);
    if (!SetSubscribeCallbackData(env,
        dataWorkerData->request,
        dataWorkerData->sortingMap,
        NO_DELETE_REASON,
        result)) {
        ANS_LOGE("Convert data to JS fail.");
    } else {
        Common::SetCallback(env, subscriber->GetCallbackInfo(CONSUME).ref, result);
    }
    napi_close_handle_scope(env, scope);
}

void SubscriberInstance::OnConsumed(const std::shared_ptr<OHOS::Notification::Notification> &request,
    const std::shared_ptr<NotificationSortingMap> &sortingMap)
{
    ANS_LOGD("called");

    if (consumeCallbackInfo_.ref == nullptr || consumeCallbackInfo_.env == nullptr) {
        ANS_LOGE("null ref or env");
        return;
    }

    if (request == nullptr) {
        ANS_LOGE("null request");
        return;
    }

    if (sortingMap == nullptr) {
        ANS_LOGE("null sortingMap");
        return;
    }
    auto notificationFlags = request->GetNotificationRequest().GetFlags();
    ANS_LOGI("key = %{public}s, sortingMap size = %{public}zu, notificationFlag = %{public}s",
        request->GetKey().c_str(), sortingMap->GetKey().size(),
        notificationFlags == nullptr ? "null" : notificationFlags->Dump().c_str());
    ANS_LOGD("OnConsumed instanceKey: %{public}s", request->GetInstanceKey().c_str());

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("null dataWorker");
        return;
    }

    dataWorker->request = request;
    dataWorker->sortingMap = sortingMap;
    dataWorker->type = Type::CONSUME;
    dataWorker->subscriber = std::static_pointer_cast<SubscriberInstance>(shared_from_this());

    CallThreadSafeFunc(dataWorker);
}

void ThreadSafeOnUpdate(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("called");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("null dataWorkerData");
        return;
    }
    auto subscriber = dataWorkerData->subscriber.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return;
    }
    napi_value result = nullptr;
    napi_handle_scope scope;
    auto status = napi_open_handle_scope(env, &scope);
    if (status != napi_ok || scope == nullptr) {
        ANS_LOGE("status: %{public}d", status);
        return;
    }
    napi_create_object(env, &result);
    if (!Common::SetNotificationSortingMap(env, dataWorkerData->sortingMap, result)) {
        ANS_LOGE("Failed to convert data to JS");
    } else {
        Common::SetCallback(env, subscriber->GetCallbackInfo(UPDATE).ref, result);
    }
    napi_close_handle_scope(env, scope);
}

void SubscriberInstance::OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap)
{
    ANS_LOGD("called");

    if (updateCallbackInfo_.ref == nullptr || updateCallbackInfo_.env == nullptr) {
        ANS_LOGE("null ref or env");
        return;
    }

    if (sortingMap == nullptr) {
        ANS_LOGE("null sortingMap");
        return;
    }
    ANS_LOGI("sortingMap size = %{public}zu", sortingMap->GetKey().size());

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("null dataWorker");
        return;
    }

    dataWorker->sortingMap = sortingMap;
    dataWorker->type = Type::UPDATE;
    dataWorker->subscriber = std::static_pointer_cast<SubscriberInstance>(shared_from_this());

    CallThreadSafeFunc(dataWorker);
}

void ThreadSafeOnConnected(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("called");
    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("null dataWorkerData");
        return;
    }
    auto subscriber = dataWorkerData->subscriber.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return;
    }

    Common::SetCallback(env, subscriber->GetCallbackInfo(CONNECTED).ref, Common::NapiGetNull(env));
}

void SubscriberInstance::OnConnected()
{
    ANS_LOGD("called");

    if (subscribeCallbackInfo_.ref == nullptr || subscribeCallbackInfo_.env == nullptr) {
        ANS_LOGE("null ref or env");
        return;
    }

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("null dataWorker");
        return;
    }

    dataWorker->type = Type::CONNECTED;
    dataWorker->subscriber = std::static_pointer_cast<SubscriberInstance>(shared_from_this());

    CallThreadSafeFunc(dataWorker);
}

void ThreadSafeOnDisconnected(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("called");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("null dataWorkerData.");
        return;
    }
    auto subscriber = dataWorkerData->subscriber.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return;
    }
    if (subscriber->GetCallbackInfo(DIS_CONNECTED).ref == nullptr) {
        ANS_LOGI("unsubscribe callback unset");
        DelSubscriberInstancesInfo(env, subscriber);
        return;
    }

    Common::SetCallback(env, subscriber->GetCallbackInfo(DIS_CONNECTED).ref, Common::NapiGetNull(env));
    DelSubscriberInstancesInfo(env, subscriber);
}

void SubscriberInstance::OnDisconnected()
{
    ANS_LOGD("called");

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("null dataWorker");
        return;
    }

    dataWorker->type = Type::DIS_CONNECTED;
    dataWorker->subscriber = std::static_pointer_cast<SubscriberInstance>(shared_from_this());

    CallThreadSafeFunc(dataWorker);
}

void ThreadSafeOnDestroy(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("called");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("null dataWorkerData");
        return;
    }
    auto subscriber = dataWorkerData->subscriber.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return;
    }
    Common::SetCallback(
        env, subscriber->GetCallbackInfo(DIE).ref, Common::NapiGetNull(env));
}

void SubscriberInstance::OnDied()
{
    ANS_LOGD("called");

    if (dieCallbackInfo_.ref == nullptr) {
        ANS_LOGE("null ref");
        return;
    }

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("null dataWorker");
        return;
    }

    dataWorker->type = Type::DIE;
    dataWorker->subscriber = std::static_pointer_cast<SubscriberInstance>(shared_from_this());

    CallThreadSafeFunc(dataWorker);
}

void ThreadSafeOnDoNotDisturbDateChange(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("called");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("null dataWorkerData");
        return;
    }
    auto subscriber = dataWorkerData->subscriber.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return;
    }
    napi_value result = nullptr;
    napi_handle_scope scope;
    auto status = napi_open_handle_scope(env, &scope);
    if (status != napi_ok || scope == nullptr) {
        ANS_LOGE("status: %{public}d", status);
        return;
    }
    napi_create_object(env, &result);

    if (!Common::SetDoNotDisturbDate(env, dataWorkerData->date, result)) {
        result = Common::NapiGetNull(env);
    }

    Common::SetCallback(env, subscriber->GetCallbackInfo(DISTURB_DATE_CHANGE).ref, result);
    napi_close_handle_scope(env, scope);
}

void SubscriberInstance::OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("called");

    onDoNotDisturbChanged(date);

    if (disturbDateCallbackInfo_.ref == nullptr || disturbDateCallbackInfo_.env == nullptr) {
        ANS_LOGE("null ref or env");
        return;
    }

    if (date == nullptr) {
        ANS_LOGE("null date");
        return;
    }

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("null dataWorker");
        return;
    }

    dataWorker->date = *date;
    dataWorker->type = Type::DISTURB_DATE_CHANGE;
    dataWorker->subscriber = std::static_pointer_cast<SubscriberInstance>(shared_from_this());

    CallThreadSafeFunc(dataWorker);
}


void ThreadSafeOnDoNotDisturbChanged(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("called");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("null dataWorkerData");
        return;
    }
    auto subscriber = dataWorkerData->subscriber.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return;
    }
    napi_value result = nullptr;
    napi_handle_scope scope;
    auto status = napi_open_handle_scope(env, &scope);
    if (status != napi_ok || scope == nullptr) {
        ANS_LOGE("status: %{public}d", status);
        return;
    }
    napi_create_object(env, &result);

    if (!Common::SetDoNotDisturbDate(env, dataWorkerData->date, result)) {
        result = Common::NapiGetNull(env);
    }

    Common::SetCallback(env, subscriber->GetCallbackInfo(DISTURB_CHANGED).ref, result);
    napi_close_handle_scope(env, scope);
}

void SubscriberInstance::onDoNotDisturbChanged(const std::shared_ptr<NotificationDoNotDisturbDate>& date)
{
    ANS_LOGD("called");

    if (disturbChangedCallbackInfo_.ref == nullptr || disturbChangedCallbackInfo_.env == nullptr) {
        ANS_LOGE("null ref or env");
        return;
    }

    if (date == nullptr) {
        ANS_LOGE("null date");
        return;
    }

    NotificationReceiveDataWorker* dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("null dataWorker");
        return;
    }

    dataWorker->date = *date;
    dataWorker->type = Type::DISTURB_CHANGED;
    dataWorker->subscriber = std::static_pointer_cast<SubscriberInstance>(shared_from_this());

    CallThreadSafeFunc(dataWorker);
}

void ThreadSafeOnEnabledNotificationChanged(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("called");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("null dataWorkerData");
        return;
    }
    auto subscriber = dataWorkerData->subscriber.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return;
    }
    napi_value result = nullptr;
    napi_handle_scope scope;
    auto status = napi_open_handle_scope(env, &scope);
    if (status != napi_ok || scope == nullptr) {
        ANS_LOGE("status: %{public}d", status);
        return;
    }
    napi_create_object(env, &result);

    if (!Common::SetEnabledNotificationCallbackData(env, dataWorkerData->callbackData, result)) {
        result = Common::NapiGetNull(env);
    }

    Common::SetCallback(env, subscriber->GetCallbackInfo(ENABLE_NOTIFICATION_CHANGED).ref, result);
    napi_close_handle_scope(env, scope);
}

void SubscriberInstance::OnEnabledNotificationChanged(
    const std::shared_ptr<EnabledNotificationCallbackData> &callbackData)
{
    ANS_LOGD("called");

    if (enabledNotificationCallbackInfo_.ref == nullptr || enabledNotificationCallbackInfo_.env == nullptr) {
        ANS_LOGE("null ref or env");
        return;
    }

    if (callbackData == nullptr) {
        ANS_LOGE("null callbackData");
        return;
    }

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("null dataWorker");
        return;
    }

    dataWorker->callbackData = *callbackData;
    dataWorker->type = Type::ENABLE_NOTIFICATION_CHANGED;
    dataWorker->subscriber = std::static_pointer_cast<SubscriberInstance>(shared_from_this());

    CallThreadSafeFunc(dataWorker);
}

void ThreadSafeOnBadgeChanged(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("called");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("null dataWorkerData");
        return;
    }
    auto subscriber = dataWorkerData->subscriber.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return;
    }
    napi_value result = nullptr;
    napi_handle_scope scope;
    auto status = napi_open_handle_scope(env, &scope);
    if (status != napi_ok || scope == nullptr) {
        ANS_LOGE("status: %{public}d", status);
        return;
    }
    napi_create_object(env, &result);

    if (!Common::SetBadgeCallbackData(env, dataWorkerData->badge, result)) {
        result = Common::NapiGetNull(env);
    }

    Common::SetCallback(env, subscriber->GetCallbackInfo(BADGE_CHANGED).ref, result);
    napi_close_handle_scope(env, scope);
}

void SubscriberInstance::OnBadgeChanged(
    const std::shared_ptr<BadgeNumberCallbackData> &badgeData)
{
    ANS_LOGD("called");

    if (setBadgeCallbackInfo_.ref == nullptr || setBadgeCallbackInfo_.env == nullptr) {
        return;
    }

    if (badgeData == nullptr) {
        ANS_LOGE("null badgeData");
        return;
    }

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("null dataWorker");
        return;
    }
    ANS_LOGD("SubscriberInstance::OnBadgeChanged instanceKey:%{public}s", badgeData->GetAppInstanceKey().c_str());
    dataWorker->badge = *badgeData;
    dataWorker->type = Type::BADGE_CHANGED;
    dataWorker->subscriber = std::static_pointer_cast<SubscriberInstance>(shared_from_this());

    CallThreadSafeFunc(dataWorker);
}

void ThreadSafeOnBadgeEnabledChanged(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("called");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("null dataWorkerData");
        return;
    }
    auto subscriber = dataWorkerData->subscriber.lock();
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return;
    }
    napi_value result = nullptr;
    napi_handle_scope scope;
    auto status = napi_open_handle_scope(env, &scope);
    if (status != napi_ok || scope == nullptr) {
        ANS_LOGE("status: %{public}d", status);
        return;
    }
    napi_create_object(env, &result);
    if (!Common::SetEnabledNotificationCallbackData(env, dataWorkerData->callbackData, result)) {
        result = Common::NapiGetNull(env);
    }

    Common::SetCallback(env, subscriber->GetCallbackInfo(BADGE_ENABLED_CHANGED).ref, result);
    napi_close_handle_scope(env, scope);
}

void SubscriberInstance::OnBadgeEnabledChanged(
    const sptr<EnabledNotificationCallbackData> &callbackData)
{
    if (setBadgeEnabledCallbackInfo_.ref == nullptr) {
        ANS_LOGE("null setBadgeEnabledCallbackInfo_.ref");
        return;
    }
    if (callbackData == nullptr) {
        ANS_LOGE("null callbackData");
        return;
    }

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("null dataWorker");
        return;
    }

    dataWorker->callbackData = *callbackData;
    dataWorker->type = Type::BADGE_ENABLED_CHANGED;
    dataWorker->subscriber = std::static_pointer_cast<SubscriberInstance>(shared_from_this());

    CallThreadSafeFunc(dataWorker);
}

void SubscriberInstance::SetThreadSafeFunction(const napi_threadsafe_function &tsfn)
{
    std::lock_guard<ffrt::mutex> lock(tsfnMutex_);
    tsfn_ = tsfn;
}

void SubscriberInstance::SetEnv(const napi_env &env)
{
    env_ = env;
}

void SubscriberInstance::SetCancelCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    canceCallbackInfo_.env = env;
    canceCallbackInfo_.ref = ref;
}

SubscriberInstance::CallbackInfo SubscriberInstance::GetCancelCallbackInfo()
{
    return canceCallbackInfo_;
}

void SubscriberInstance::SetConsumeCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    consumeCallbackInfo_.env = env;
    consumeCallbackInfo_.ref = ref;
}

SubscriberInstance::CallbackInfo SubscriberInstance::GetConsumeCallbackInfo()
{
    return consumeCallbackInfo_;
}

void SubscriberInstance::SetUpdateCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    updateCallbackInfo_.env = env;
    updateCallbackInfo_.ref = ref;
}

SubscriberInstance::CallbackInfo SubscriberInstance::GetUpdateCallbackInfo()
{
    return updateCallbackInfo_;
}

void SubscriberInstance::SetSubscribeCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    subscribeCallbackInfo_.env = env;
    subscribeCallbackInfo_.ref = ref;
}

SubscriberInstance::CallbackInfo SubscriberInstance::GetSubscribeCallbackInfo()
{
    return subscribeCallbackInfo_;
}

void SubscriberInstance::SetUnsubscribeCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    unsubscribeCallbackInfo_.env = env;
    unsubscribeCallbackInfo_.ref = ref;
}

SubscriberInstance::CallbackInfo SubscriberInstance::GetUnsubscribeCallbackInfo()
{
    return unsubscribeCallbackInfo_;
}

void SubscriberInstance::SetDieCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    dieCallbackInfo_.env = env;
    dieCallbackInfo_.ref = ref;
}

SubscriberInstance::CallbackInfo SubscriberInstance::GetDieCallbackInfo()
{
    return dieCallbackInfo_;
}

void SubscriberInstance::SetDisturbModeCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    disturbModeCallbackInfo_.env = env;
    disturbModeCallbackInfo_.ref = ref;
}

SubscriberInstance::CallbackInfo SubscriberInstance::GetDisturbModeCallbackInfo()
{
    return disturbModeCallbackInfo_;
}

void SubscriberInstance::SetEnabledNotificationCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    enabledNotificationCallbackInfo_.env = env;
    enabledNotificationCallbackInfo_.ref = ref;
}

SubscriberInstance::CallbackInfo SubscriberInstance::GetEnabledNotificationCallbackInfo()
{
    return enabledNotificationCallbackInfo_;
}

void SubscriberInstance::SetDisturbDateCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    disturbDateCallbackInfo_.env = env;
    disturbDateCallbackInfo_.ref = ref;
}

SubscriberInstance::CallbackInfo SubscriberInstance::GetDisturbDateCallbackInfo()
{
    return disturbDateCallbackInfo_;
}

void SubscriberInstance::SetDisturbChangedCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    disturbChangedCallbackInfo_.env = env;
    disturbChangedCallbackInfo_.ref = ref;
}

SubscriberInstance::CallbackInfo SubscriberInstance::GetDisturbChangedCallbackInfo()
{
    return disturbChangedCallbackInfo_;
}

void SubscriberInstance::SetBadgeCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    setBadgeCallbackInfo_.env = env;
    setBadgeCallbackInfo_.ref = ref;
}

SubscriberInstance::CallbackInfo SubscriberInstance::GetBadgeCallbackInfo()
{
    return setBadgeCallbackInfo_;
}

void SubscriberInstance::SetBadgeEnabledCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    setBadgeEnabledCallbackInfo_.env = env;
    setBadgeEnabledCallbackInfo_.ref = ref;
}

SubscriberInstance::CallbackInfo SubscriberInstance::GetBadgeEnabledCallbackInfo()
{
    return setBadgeEnabledCallbackInfo_;
}

void SubscriberInstance::SetBatchCancelCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    batchCancelCallbackInfo_.env = env;
    batchCancelCallbackInfo_.ref = ref;
}

SubscriberInstance::CallbackInfo SubscriberInstance::GetBatchCancelCallbackInfo()
{
    return batchCancelCallbackInfo_;
}

void SubscriberInstance::SetCallbackInfo(const napi_env &env, const std::string &type, const napi_ref &ref)
{
    if (type == CONSUME) {
        SetConsumeCallbackInfo(env, ref);
    } else if (type == CANCEL) {
        SetCancelCallbackInfo(env, ref);
    } else if (type == UPDATE) {
        SetUpdateCallbackInfo(env, ref);
    } else if (type == CONNECTED) {
        SetSubscribeCallbackInfo(env, ref);
    } else if (type == DIS_CONNECTED) {
        SetUnsubscribeCallbackInfo(env, ref);
    } else if (type == DIE) {
        SetDieCallbackInfo(env, ref);
    } else if (type == DISTURB_MODE_CHANGE) {
        SetDisturbModeCallbackInfo(env, ref);
    } else if (type == DISTURB_DATE_CHANGE) {
        SetDisturbDateCallbackInfo(env, ref);
    } else if (type == DISTURB_CHANGED) {
        SetDisturbChangedCallbackInfo(env, ref);
    } else if (type == ENABLE_NOTIFICATION_CHANGED) {
        SetEnabledNotificationCallbackInfo(env, ref);
    } else if (type == BADGE_CHANGED) {
        SetBadgeCallbackInfo(env, ref);
    } else if (type == BADGE_ENABLED_CHANGED) {
        SetBadgeEnabledCallbackInfo(env, ref);
    } else if (type == BATCH_CANCEL) {
        SetBatchCancelCallbackInfo(env, ref);
    } else {
        ANS_LOGW("type is error");
    }
}

SubscriberInstance::CallbackInfo SubscriberInstance::GetCallbackInfo(const std::string &type)
{
    if (type == CONSUME) {
        return GetConsumeCallbackInfo();
    } else if (type == CANCEL) {
        return GetCancelCallbackInfo();
    } else if (type == UPDATE) {
        return GetUpdateCallbackInfo();
    } else if (type == CONNECTED) {
        return GetSubscribeCallbackInfo();
    } else if (type == DIS_CONNECTED) {
        return GetUnsubscribeCallbackInfo();
    } else if (type == DIE) {
        return GetDieCallbackInfo();
    } else if (type == DISTURB_MODE_CHANGE) {
        return GetDisturbModeCallbackInfo();
    } else if (type == DISTURB_DATE_CHANGE) {
        return GetDisturbDateCallbackInfo();
    } else if (type == DISTURB_CHANGED) {
        return GetDisturbChangedCallbackInfo();
    } else if (type == ENABLE_NOTIFICATION_CHANGED) {
        return GetEnabledNotificationCallbackInfo();
    } else if (type == BADGE_CHANGED) {
        return GetBadgeCallbackInfo();
    } else if (type == BADGE_ENABLED_CHANGED) {
        return GetBadgeEnabledCallbackInfo();
    } else if (type == BATCH_CANCEL) {
        return GetBatchCancelCallbackInfo();
    } else {
        ANS_LOGW("type is error");
        return {nullptr, nullptr};
    }
}

bool HasNotificationSubscriber(const napi_env &env, const napi_value &value, SubscriberInstancesInfo &subscriberInfo)
{
    std::lock_guard<ffrt::mutex> lock(mutex_);
    for (auto vec : subscriberInstances_) {
        napi_value callback = nullptr;
        napi_get_reference_value(env, vec.ref, &callback);
        bool isEquals = false;
        napi_strict_equals(env, value, callback, &isEquals);
        if (isEquals) {
            subscriberInfo = vec;
            return true;
        }
    }
    return false;
}

void ThreadFinished(napi_env env, void* data, [[maybe_unused]] void* context)
{
    ANS_LOGD("called");
}

void ThreadSafeCommon(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGD("called");
    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    switch (dataWorkerData->type) {
        case Type::CANCEL:
            ThreadSafeOnCancel(env, jsCallback, context, data);
            break;
        case Type::BATCH_CANCEL:
            ThreadSafeOnBatchCancel(env, jsCallback, context, data);
            break;
        case Type::CONSUME:
            ThreadSafeOnConsumed(env, jsCallback, context, data);
            break;
        case Type::UPDATE:
            ThreadSafeOnUpdate(env, jsCallback, context, data);
            break;
        case Type::CONNECTED:
            ThreadSafeOnConnected(env, jsCallback, context, data);
            break;
        case Type::DIS_CONNECTED:
            ThreadSafeOnDisconnected(env, jsCallback, context, data);
            break;
        case Type::DIE:
            ThreadSafeOnDestroy(env, jsCallback, context, data);
            break;
        case Type::DISTURB_DATE_CHANGE:
            ThreadSafeOnDoNotDisturbDateChange(env, jsCallback, context, data);
            break;
        case Type::DISTURB_CHANGED:
            ThreadSafeOnDoNotDisturbChanged(env, jsCallback, context, data);
            break;
        case Type::ENABLE_NOTIFICATION_CHANGED:
            ThreadSafeOnEnabledNotificationChanged(env, jsCallback, context, data);
            break;
        case Type::BADGE_CHANGED:
            ThreadSafeOnBadgeChanged(env, jsCallback, context, data);
            break;
        case Type::BADGE_ENABLED_CHANGED:
            ThreadSafeOnBadgeEnabledChanged(env, jsCallback, context, data);
            break;
        default:
            break;
    }
    delete dataWorkerData;
    dataWorkerData = nullptr;
}

napi_value GetNotificationSubscriber(
    const napi_env &env, const napi_value &value, SubscriberInstancesInfo &subscriberInfo)
{
    ANS_LOGD("called");
    bool hasProperty = false;
    napi_valuetype valuetype = napi_undefined;
    napi_ref result = nullptr;

    subscriberInfo.subscriber = std::make_shared<SubscriberInstance>();
    if (subscriberInfo.subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        std::string msg = "Mandatory parameters are left unspecified. subscriber is null";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    napi_create_reference(env, value, 1, &subscriberInfo.ref);

    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "tsfn", NAPI_AUTO_LENGTH, &resourceName);
    napi_threadsafe_function tsfn = nullptr;
    napi_create_threadsafe_function(env, nullptr, nullptr, resourceName, 0, 1, subscriberInfo.ref,
        ThreadFinished, nullptr, ThreadSafeCommon, &tsfn);
    subscriberInfo.subscriber->SetThreadSafeFunction(tsfn);
    subscriberInfo.subscriber->SetEnv(env);

    // onConsume?:(data: SubscribeCallbackData) => void
    NAPI_CALL(env, napi_has_named_property(env, value, "onConsume", &hasProperty));
    if (hasProperty) {
        napi_value nOnConsumed = nullptr;
        napi_get_named_property(env, value, "onConsume", &nOnConsumed);
        NAPI_CALL(env, napi_typeof(env, nOnConsumed, &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, nOnConsumed, 1, &result);
        subscriberInfo.subscriber->SetCallbackInfo(env, CONSUME, result);
    }
    // onCancel?:(data: SubscribeCallbackData) => void
    NAPI_CALL(env, napi_has_named_property(env, value, "onCancel", &hasProperty));
    if (hasProperty) {
        napi_value nOnCanceled = nullptr;
        napi_get_named_property(env, value, "onCancel", &nOnCanceled);
        NAPI_CALL(env, napi_typeof(env, nOnCanceled, &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, nOnCanceled, 1, &result);
        subscriberInfo.subscriber->SetCallbackInfo(env, CANCEL, result);
    }
    // onUpdate?:(data: NotificationSortingMap) => void
    NAPI_CALL(env, napi_has_named_property(env, value, "onUpdate", &hasProperty));
    if (hasProperty) {
        napi_value nOnUpdate = nullptr;
        napi_get_named_property(env, value, "onUpdate", &nOnUpdate);
        NAPI_CALL(env, napi_typeof(env, nOnUpdate, &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, nOnUpdate, 1, &result);
        subscriberInfo.subscriber->SetCallbackInfo(env, UPDATE, result);
    }
    // onConnect?:() => void
    NAPI_CALL(env, napi_has_named_property(env, value, "onConnect", &hasProperty));
    if (hasProperty) {
        napi_value nOnConnected = nullptr;
        napi_get_named_property(env, value, "onConnect", &nOnConnected);
        NAPI_CALL(env, napi_typeof(env, nOnConnected, &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, nOnConnected, 1, &result);
        subscriberInfo.subscriber->SetCallbackInfo(env, CONNECTED, result);
    }
    // onDisconnect?:() => void
    NAPI_CALL(env, napi_has_named_property(env, value, "onDisconnect", &hasProperty));
    if (hasProperty) {
        napi_value nOnDisConnect = nullptr;
        napi_get_named_property(env, value, "onDisconnect", &nOnDisConnect);
        NAPI_CALL(env, napi_typeof(env, nOnDisConnect, &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, nOnDisConnect, 1, &result);
        subscriberInfo.subscriber->SetCallbackInfo(env, DIS_CONNECTED, result);
    }
    // onDestroy?:() => void
    NAPI_CALL(env, napi_has_named_property(env, value, "onDestroy", &hasProperty));
    if (hasProperty) {
        napi_value nOnDied = nullptr;
        napi_get_named_property(env, value, "onDestroy", &nOnDied);
        NAPI_CALL(env, napi_typeof(env, nOnDied, &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, nOnDied, 1, &result);
        subscriberInfo.subscriber->SetCallbackInfo(env, DIE, result);
    }
    // onDisturbModeChange?:(mode: notification.DoNotDisturbMode) => void
    NAPI_CALL(env, napi_has_named_property(env, value, "onDisturbModeChange", &hasProperty));
    if (hasProperty) {
        napi_value nOnDisturbModeChanged = nullptr;
        napi_get_named_property(env, value, "onDisturbModeChange", &nOnDisturbModeChanged);
        NAPI_CALL(env, napi_typeof(env, nOnDisturbModeChanged, &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, nOnDisturbModeChanged, 1, &result);
        subscriberInfo.subscriber->SetCallbackInfo(env, DISTURB_MODE_CHANGE, result);
    }

    // onDoNotDisturbDateChange?:(mode: notification.DoNotDisturbDate) => void
    NAPI_CALL(env, napi_has_named_property(env, value, "onDoNotDisturbDateChange", &hasProperty));
    if (hasProperty) {
        napi_value nOnDisturbDateChanged = nullptr;
        napi_get_named_property(env, value, "onDoNotDisturbDateChange", &nOnDisturbDateChanged);
        NAPI_CALL(env, napi_typeof(env, nOnDisturbDateChanged, &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, nOnDisturbDateChanged, 1, &result);
        subscriberInfo.subscriber->SetCallbackInfo(env, DISTURB_DATE_CHANGE, result);
    }

    // onDoNotDisturbChanged?:(mode: notificationManager.DoNotDisturbDate) => void
    NAPI_CALL(env, napi_has_named_property(env, value, "onDoNotDisturbChanged", &hasProperty));
    if (hasProperty) {
        napi_value nOnDoNotDisturbChanged = nullptr;
        napi_get_named_property(env, value, "onDoNotDisturbChanged", &nOnDoNotDisturbChanged);
        NAPI_CALL(env, napi_typeof(env, nOnDoNotDisturbChanged, &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, nOnDoNotDisturbChanged, 1, &result);
        subscriberInfo.subscriber->SetCallbackInfo(env, DISTURB_CHANGED, result);
    }

    // onEnabledNotificationChanged?:(data: notification.EnabledNotificationCallbackData) => void
    NAPI_CALL(env, napi_has_named_property(env, value, "onEnabledNotificationChanged", &hasProperty));
    if (hasProperty) {
        napi_value nOnEnabledNotificationChanged = nullptr;
        napi_get_named_property(env, value, "onEnabledNotificationChanged", &nOnEnabledNotificationChanged);
        NAPI_CALL(env, napi_typeof(env, nOnEnabledNotificationChanged, &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, nOnEnabledNotificationChanged, 1, &result);
        subscriberInfo.subscriber->SetCallbackInfo(env, ENABLE_NOTIFICATION_CHANGED, result);
    }

    // onBadgeChanged?:(data: BadgeNumberCallbackData) => void
    NAPI_CALL(env, napi_has_named_property(env, value, "onBadgeChanged", &hasProperty));
    if (hasProperty) {
        napi_value nOnBadgeChanged = nullptr;
        napi_get_named_property(env, value, "onBadgeChanged", &nOnBadgeChanged);
        NAPI_CALL(env, napi_typeof(env, nOnBadgeChanged, &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, nOnBadgeChanged, 1, &result);
        subscriberInfo.subscriber->SetCallbackInfo(env, BADGE_CHANGED, result);
    }

    // onBadgeEnabledChanged?:(data: EnabledNotificationCallbackData) => void
    NAPI_CALL(env, napi_has_named_property(env, value, "onBadgeEnabledChanged", &hasProperty));
    if (hasProperty) {
        napi_value nOnBadgeEnabledChanged = nullptr;
        napi_get_named_property(env, value, "onBadgeEnabledChanged", &nOnBadgeEnabledChanged);
        NAPI_CALL(env, napi_typeof(env, nOnBadgeEnabledChanged, &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, nOnBadgeEnabledChanged, 1, &result);
        subscriberInfo.subscriber->SetCallbackInfo(env, BADGE_ENABLED_CHANGED, result);
    }

    // onBatchCancel?:(data: Array<SubscribeCallbackData>) => void
    NAPI_CALL(env, napi_has_named_property(env, value, "onBatchCancel", &hasProperty));
    if (hasProperty) {
        napi_value onBatchCancel = nullptr;
        napi_get_named_property(env, value, "onBatchCancel", &onBatchCancel);
        NAPI_CALL(env, napi_typeof(env, onBatchCancel, &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, onBatchCancel, 1, &result);
        subscriberInfo.subscriber->SetCallbackInfo(env, BATCH_CANCEL, result);
    }

    return Common::NapiGetNull(env);
}

bool AddSubscriberInstancesInfo(const napi_env &env, const SubscriberInstancesInfo &subscriberInfo)
{
    ANS_LOGD("called");
    if (subscriberInfo.ref == nullptr) {
        ANS_LOGE("null ref");
        return false;
    }
    if (subscriberInfo.subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return false;
    }
    std::lock_guard<ffrt::mutex> lock(mutex_);
    subscriberInstances_.emplace_back(subscriberInfo);

    return true;
}

bool DelSubscriberInstancesInfo(const napi_env &env, const std::shared_ptr<SubscriberInstance> subscriber)
{
    ANS_LOGD("called");
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return false;
    }

    std::lock_guard<ffrt::mutex> lock(mutex_);
    for (auto it = subscriberInstances_.begin(); it != subscriberInstances_.end(); ++it) {
        if ((*it).subscriber == subscriber) {
            DelDeletingSubscriber((*it).subscriber);
            subscriberInstances_.erase(it);
            return true;
        }
    }
    return false;
}
napi_value ParseParameters(const napi_env &env, const napi_callback_info &info,
    NotificationSubscribeInfo &subscriberInfo, std::shared_ptr<SubscriberInstance> &subscriber, napi_ref &callback)
{
    ANS_LOGD("called");

    size_t argc = SUBSRIBE_MAX_PARA;
    napi_value argv[SUBSRIBE_MAX_PARA] = {nullptr};
    napi_value thisVar = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < 1) {
        ANS_LOGE("Wrong number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;

    // argv[0]:subscriber
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type for arg0. NotificationSubscriber object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be NotificationSubscriber.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    SubscriberInstancesInfo subscriberInstancesInfo;
    if (!HasNotificationSubscriber(env, argv[PARAM0], subscriberInstancesInfo)) {
        if (GetNotificationSubscriber(env, argv[PARAM0], subscriberInstancesInfo) == nullptr) {
            ANS_LOGE("NotificationSubscriber parse failed");
            return nullptr;
        }
        if (!AddSubscriberInstancesInfo(env, subscriberInstancesInfo)) {
            ANS_LOGE("AddSubscriberInstancesInfo add failed");
            return nullptr;
        }
    }
    subscriber = subscriberInstancesInfo.subscriber;

    // argv[1]:callback or NotificationSubscribeInfo
    if (argc >= SUBSRIBE_MAX_PARA - 1) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if ((valuetype != napi_function) && (valuetype != napi_object)) {
            ANS_LOGE("Wrong argument type for arg1."
                "Function or NotificationSubscribeInfo object expected. Excute promise");
            return Common::NapiGetNull(env);
        }
        if (valuetype == napi_function) {
            napi_create_reference(env, argv[PARAM1], 1, &callback);
        } else {
            if (Common::GetNotificationSubscriberInfo(env, argv[PARAM1], subscriberInfo) == nullptr) {
                ANS_LOGE("NotificationSubscribeInfo parse failed");
                return nullptr;
            }
        }
    }

    // argv[2]:callback
    if (argc >= SUBSRIBE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM2], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function enforce promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM2], 1, &callback);
    }

    return Common::NapiGetNull(env);
}

napi_value Subscribe(napi_env env, napi_callback_info info)
{
    ANS_LOGD("called");

    napi_ref callback = nullptr;
    std::shared_ptr<SubscriberInstance> objectInfo = nullptr;
    NotificationSubscribeInfo subscriberInfo;
    if (ParseParameters(env, info, subscriberInfo, objectInfo, callback) == nullptr) {
        ANS_LOGD("null ParseParameters");
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoSubscribe *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoSubscribe {
        .env = env, .asyncWork = nullptr, .objectInfo = objectInfo, .subscriberInfo = subscriberInfo
    };
    if (!asynccallbackinfo) {
        ANS_LOGD("null asynccallbackinfo");
        return Common::JSParaError(env, callback);
    }
    napi_value promise = nullptr;
    Common::PaddingCallbackPromiseInfo(env, callback, asynccallbackinfo->info, promise);

    ANS_LOGD("Create subscribeNotification string.");
    napi_value resourceName = nullptr;
    napi_create_string_latin1(env, "subscribeNotification", NAPI_AUTO_LENGTH, &resourceName);
    // Asynchronous function call
    napi_create_async_work(env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            ANS_LOGD("Subscribe work excuted.");
            if (!data) {
                ANS_LOGE("Invalid asynccallbackinfo!");
                return;
            }
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoSubscribe *>(data);
            if (asynccallbackinfo) {
                if (asynccallbackinfo->subscriberInfo.hasSubscribeInfo) {
                    ANS_LOGD("Subscribe with NotificationSubscribeInfo excute.");
                    sptr<OHOS::Notification::NotificationSubscribeInfo> subscribeInfo =
                        new (std::nothrow) OHOS::Notification::NotificationSubscribeInfo();
                    if (subscribeInfo == nullptr) {
                        ANS_LOGE("null subscribeInfo");
                        asynccallbackinfo->info.errorCode = OHOS::Notification::ErrorCode::ERR_ANS_NO_MEMORY;
                        return;
                    }
                    subscribeInfo->AddAppNames(asynccallbackinfo->subscriberInfo.bundleNames);
                    subscribeInfo->AddAppUserId(asynccallbackinfo->subscriberInfo.userId);
                    asynccallbackinfo->info.errorCode =
                        NotificationHelper::SubscribeNotification(asynccallbackinfo->objectInfo, subscribeInfo);
                } else {
                    ANS_LOGD("SubscribeNotification execute.");
                    asynccallbackinfo->info.errorCode =
                        NotificationHelper::SubscribeNotification(asynccallbackinfo->objectInfo);
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("Subscribe work complete.");
            if (!data) {
                ANS_LOGE("null data");
                return;
            }
            auto asynccallbackinfo = reinterpret_cast<AsyncCallbackInfoSubscribe *>(data);
            if (asynccallbackinfo) {
                Common::ReturnCallbackPromise(env, asynccallbackinfo->info, Common::NapiGetNull(env));
                if (asynccallbackinfo->info.callback != nullptr) {
                    ANS_LOGD("Delete subscribe callback reference.");
                    napi_delete_reference(env, asynccallbackinfo->info.callback);
                }
                napi_delete_async_work(env, asynccallbackinfo->asyncWork);
                delete asynccallbackinfo;
                asynccallbackinfo = nullptr;
            }
            ANS_LOGD("Subscribe work complete end.");
        },
        (void *)asynccallbackinfo,
        &asynccallbackinfo->asyncWork);

    napi_add_env_cleanup_hook(env, ClearEnvCallback, objectInfo.get());
    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("null isCallback");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

bool AddDeletingSubscriber(std::shared_ptr<SubscriberInstance> subscriber)
{
    std::lock_guard<ffrt::mutex> lock(delMutex_);
    auto iter = std::find(DeletingSubscriber.begin(), DeletingSubscriber.end(), subscriber);
    if (iter != DeletingSubscriber.end()) {
        return false;
    }

    DeletingSubscriber.push_back(subscriber);
    return true;
}

void DelDeletingSubscriber(std::shared_ptr<SubscriberInstance> subscriber)
{
    std::lock_guard<ffrt::mutex> lock(delMutex_);
    auto iter = std::find(DeletingSubscriber.begin(), DeletingSubscriber.end(), subscriber);
    if (iter != DeletingSubscriber.end()) {
        DeletingSubscriber.erase(iter);
    }
}

napi_value GetParamOperationInfoSub(const napi_env &env, const napi_value &content, OperationInfo& operationInfo)
{
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, content, "operationType", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, content, "operationType", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            return nullptr;
        }
        int32_t code;
        NAPI_CALL(env, napi_get_value_int32(env, result, &code));
        operationInfo.operationType = code;
    }

    NAPI_CALL(env, napi_has_named_property(env, content, "buttonIndex", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, content, "buttonIndex", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_number) {
            return nullptr;
        }

        int32_t code;
        NAPI_CALL(env, napi_get_value_int32(env, result, &code));
        operationInfo.btnIndex = code;
    }
    return Common::NapiGetNull(env);
}
 
napi_value GetParamOperationInfo(const napi_env &env, const napi_value &content, OperationInfo& operationInfo)
{
    operationInfo.withOperationInfo = true;
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, content, &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type for arg1. object expected.");
        std::string msg = "Incorrect parameter type. The type of operationInfo must be object.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    size_t strLen = 0;
    napi_value result = nullptr;
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, content, "actionName", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, content, "actionName", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. String expected.");
            std::string msg = "Incorrect parameter types. The type of actionName must be string.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        char str[STR_MAX_SIZE] = {0};
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, STR_MAX_SIZE - 1, &strLen));
        operationInfo.actionName = str;
    }

    NAPI_CALL(env, napi_has_named_property(env, content, "userInput", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, content, "userInput", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_string) {
            ANS_LOGE("Wrong argument type. String expected.");
            std::string msg = "Incorrect parameter types. The type of userInput must be string.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        char str[LONG_STR_MAX_SIZE] = {0};
        NAPI_CALL(env, napi_get_value_string_utf8(env, result, str, LONG_STR_MAX_SIZE - 1, &strLen));
        operationInfo.userInput = str;
    }

    if (!operationInfo.userInput.empty()) {
        return Common::NapiGetNull(env);
    }
    return GetParamOperationInfoSub(env, content, operationInfo);
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info, std::string &hashCode,
    napi_value& thisVar, OperationInfo& operationInfo)
{
    ANS_LOGD("called");

    size_t argc = DISTRIBUTE_REPLY_PARA;
    napi_value argv[DISTRIBUTE_REPLY_PARA] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    if (argc < DISTRIBUTE_JUMP_PARA) {
        ANS_LOGE("Wrong number of arguments");
        Common::NapiThrow(env, ERROR_PARAM_INVALID, MANDATORY_PARAMETER_ARE_LEFT_UNSPECIFIED);
        return nullptr;
    }

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype == napi_string) {
        size_t strLen = 0;
        char str[STR_MAX_SIZE] = {0};
        NAPI_CALL(env, napi_get_value_string_utf8(env, argv[PARAM0], str, STR_MAX_SIZE - 1, &strLen));
        hashCode = str;
    } else {
        ANS_LOGE("Wrong argument type for arg0. string expected.");
        std::string msg = "Incorrect parameter type. The type of hashcode must be string.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    if (hashCode.empty()) {
        ANS_LOGE("Wrong argument type for arg0. not empty expected.");
        std::string msg = "Incorrect parameter type. The type of hashcode must be not null.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    if (argc > DISTRIBUTE_JUMP_PARA) {
        if (GetParamOperationInfo(env, argv[PARAM1], operationInfo) == nullptr) {
            return Common::NapiGetUndefined(env);
        }
    }

    return Common::NapiGetNull(env);
}
}  // namespace NotificationNapi
}  // namespace OHOS
