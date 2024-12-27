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
#include "inner_event.h"
#include <mutex>
#include <uv.h>

namespace OHOS {
namespace NotificationNapi {
const int32_t SUBSRIBE_MAX_PARA = 3;
const int32_t NO_DELETE_REASON = -1;

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
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    std::shared_ptr<OHOS::Notification::Notification> request;
    std::vector<std::shared_ptr<OHOS::Notification::Notification>> requestList;
    std::shared_ptr<NotificationSortingMap> sortingMap;
    NotificationDoNotDisturbDate date;
    EnabledNotificationCallbackData callbackData;
    BadgeNumberCallbackData badge;
    int32_t deleteReason = 0;
    int32_t result = 0;
    int32_t disturbMode = 0;
    std::shared_ptr<SubscriberInstance> subscriber = nullptr;
    Type type;
};

napi_value SetSubscribeCallbackData(const napi_env &env,
    const std::shared_ptr<OHOS::Notification::Notification> &request,
    const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason, napi_value &result)
{
    ANS_LOGD("enter");
    if (request == nullptr) {
        ANS_LOGE("request is null");
        return Common::NapiGetBoolean(env, false);
    }

    if (sortingMap == nullptr) {
        ANS_LOGE("sortingMap is null");
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

SubscriberInstance::SubscriberInstance()
{}

SubscriberInstance::~SubscriberInstance()
{
    if (tsfn_ != nullptr) {
        napi_release_threadsafe_function(tsfn_, napi_tsfn_release);
    }
    if (canceCallbackInfo_.ref != nullptr) {
        napi_delete_reference(canceCallbackInfo_.env, canceCallbackInfo_.ref);
    }
    if (consumeCallbackInfo_.ref != nullptr) {
        napi_delete_reference(consumeCallbackInfo_.env, consumeCallbackInfo_.ref);
    }
    if (updateCallbackInfo_.ref != nullptr) {
        napi_delete_reference(updateCallbackInfo_.env, updateCallbackInfo_.ref);
    }
    if (subscribeCallbackInfo_.ref != nullptr) {
        napi_delete_reference(subscribeCallbackInfo_.env, subscribeCallbackInfo_.ref);
    }
    if (unsubscribeCallbackInfo_.ref != nullptr) {
        napi_delete_reference(unsubscribeCallbackInfo_.env, unsubscribeCallbackInfo_.ref);
    }
    if (dieCallbackInfo_.ref != nullptr) {
        napi_delete_reference(dieCallbackInfo_.env, dieCallbackInfo_.ref);
    }
    if (disturbModeCallbackInfo_.ref != nullptr) {
        napi_delete_reference(disturbModeCallbackInfo_.env, disturbModeCallbackInfo_.ref);
    }
    if (enabledNotificationCallbackInfo_.ref != nullptr) {
        napi_delete_reference(enabledNotificationCallbackInfo_.env, enabledNotificationCallbackInfo_.ref);
    }
    if (batchCancelCallbackInfo_.ref != nullptr) {
        napi_delete_reference(batchCancelCallbackInfo_.env, batchCancelCallbackInfo_.ref);
    }
}

void ThreadSafeOnCancel(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("OnCanceled thread safe start");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("Create dataWorkerData failed.");
        return;
    }

    napi_value result = nullptr;
    napi_handle_scope scope;
    napi_open_handle_scope(dataWorkerData->env, &scope);
    if (scope == nullptr) {
        ANS_LOGE("Scope is null");
        return;
    }
    napi_create_object(dataWorkerData->env, &result);
    if (!SetSubscribeCallbackData(dataWorkerData->env,
        dataWorkerData->request,
        dataWorkerData->sortingMap,
        dataWorkerData->deleteReason,
        result)) {
        ANS_LOGE("Failed to convert data to JS");
    } else {
        Common::SetCallback(dataWorkerData->env, dataWorkerData->ref, result);
    }
    napi_close_handle_scope(dataWorkerData->env, scope);

    delete dataWorkerData;
    dataWorkerData = nullptr;
}

void SubscriberInstance::OnCanceled(const std::shared_ptr<OHOS::Notification::Notification> &request,
    const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason)
{
    ANS_LOGD("enter");

    if (canceCallbackInfo_.ref == nullptr || canceCallbackInfo_.env == nullptr) {
        ANS_LOGI("cancel callback or env unset");
        return;
    }

    if (request == nullptr) {
        ANS_LOGE("request is null");
        return;
    }

    if (sortingMap == nullptr) {
        ANS_LOGE("sortingMap is null");
        return;
    }
    ANS_LOGI("OnCanceled NotificationKey = %{public}s. sortingMap size = %{public}zu. deleteReason = %{public}d",
        request->GetKey().c_str(), sortingMap->GetKey().size(), deleteReason);

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("DataWorker is nullptr.");
        return;
    }

    dataWorker->request = request;
    dataWorker->sortingMap = sortingMap;
    dataWorker->deleteReason = deleteReason;
    dataWorker->env = canceCallbackInfo_.env;
    dataWorker->ref = canceCallbackInfo_.ref;
    dataWorker->type = Type::CANCEL;

    napi_acquire_threadsafe_function(tsfn_);
    napi_call_threadsafe_function(tsfn_, dataWorker, napi_tsfn_nonblocking);
    napi_release_threadsafe_function(tsfn_, napi_tsfn_release);
}

void ThreadSafeOnBatchCancel(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("OnBatchCancel thread safe start");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("Create dataWorkerData failed.");
        return;
    }

    napi_value resultArray = nullptr;
    napi_handle_scope scope;
    napi_open_handle_scope(dataWorkerData->env, &scope);
    if (scope == nullptr) {
        ANS_LOGE("Scope is null");
        return;
    }
    napi_create_array(dataWorkerData->env, &resultArray);
    int index = 0;
    for (auto request : dataWorkerData->requestList) {
        napi_value result = nullptr;
        napi_create_object(dataWorkerData->env, &result);
        if (SetSubscribeCallbackData(dataWorkerData->env, request,
            dataWorkerData->sortingMap, dataWorkerData->deleteReason, result)) {
            napi_set_element(dataWorkerData->env, resultArray, index, result);
            index++;
        }
    }
    uint32_t elementCount = 0;
    napi_get_array_length(dataWorkerData->env, resultArray, &elementCount);
    ANS_LOGI("notification array length: %{public}d ", elementCount);
    if (elementCount > 0) {
        Common::SetCallback(dataWorkerData->env, dataWorkerData->ref, resultArray);
    }

    napi_close_handle_scope(dataWorkerData->env, scope);

    delete dataWorkerData;
    dataWorkerData = nullptr;
}

void SubscriberInstance::OnBatchCanceled(const std::vector<std::shared_ptr<OHOS::Notification::Notification>>
    &requestList, const std::shared_ptr<NotificationSortingMap> &sortingMap, int32_t deleteReason)
{
    ANS_LOGI("OnBatchCancel");
    if (batchCancelCallbackInfo_.ref == nullptr || batchCancelCallbackInfo_.env == nullptr) {
        ANS_LOGI("batchCancelCallbackInfo_ callback or env unset");
        return;
    }
    if (requestList.empty()) {
        ANS_LOGE("requestList is empty");
        return;
    }
    if (sortingMap == nullptr) {
        ANS_LOGE("sortingMap is null");
        return;
    }
    ANS_LOGI("OnBatchCancel sortingMap size = %{public}zu", sortingMap->GetKey().size());
    ANS_LOGI("OnBatchCancel deleteReason = %{public}d", deleteReason);
    std::string notificationKeys = "";
    for (auto notification : requestList) {
        notificationKeys.append(notification->GetKey()).append("-");
    }
    ANS_LOGI("OnBatchCancel. cancel keys = %{public}s", notificationKeys.c_str());

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("DataWorker is nullptr.");
        return;
    }
    dataWorker->requestList = requestList;
    dataWorker->sortingMap = sortingMap;
    dataWorker->deleteReason = deleteReason;
    dataWorker->env = batchCancelCallbackInfo_.env;
    dataWorker->ref = batchCancelCallbackInfo_.ref;
    dataWorker->type = Type::BATCH_CANCEL;
    
    napi_acquire_threadsafe_function(tsfn_);
    napi_call_threadsafe_function(tsfn_, dataWorker, napi_tsfn_nonblocking);
    napi_release_threadsafe_function(tsfn_, napi_tsfn_release);
    return;
}

bool SubscriberInstance::HasOnBatchCancelCallback()
{
    if (batchCancelCallbackInfo_.ref == nullptr) {
        ANS_LOGI("batchCancelCallbackInfo_ callback unset");
        return false;
    }
    return true;
}

void ThreadSafeOnConsumed(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("OnConsumed thread safe start");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGD("dataWorkerData is null.");
        return;
    }
    napi_value result = nullptr;
    napi_handle_scope scope;
    napi_open_handle_scope(dataWorkerData->env, &scope);
    if (scope == nullptr) {
        ANS_LOGE("Scope is null");
        return;
    }
    napi_create_object(dataWorkerData->env, &result);
    if (!SetSubscribeCallbackData(dataWorkerData->env,
        dataWorkerData->request,
        dataWorkerData->sortingMap,
        NO_DELETE_REASON,
        result)) {
        ANS_LOGE("Convert data to JS fail.");
    } else {
        Common::SetCallback(dataWorkerData->env, dataWorkerData->ref, result);
    }
    napi_close_handle_scope(dataWorkerData->env, scope);

    delete dataWorkerData;
    dataWorkerData = nullptr;
}

void SubscriberInstance::OnConsumed(const std::shared_ptr<OHOS::Notification::Notification> &request,
    const std::shared_ptr<NotificationSortingMap> &sortingMap)
{
    ANS_LOGD("enter");

    if (consumeCallbackInfo_.ref == nullptr || consumeCallbackInfo_.env == nullptr) {
        ANS_LOGI("consume callback or env unset");
        return;
    }

    if (tsfn_ == nullptr) {
        ANS_LOGI("consume tsfn is null");
        return;
    }

    if (request == nullptr) {
        ANS_LOGE("request is nullptr.");
        return;
    }

    if (sortingMap == nullptr) {
        ANS_LOGE("sortingMap is nullptr.");
        return;
    }
    auto notificationFlags = request->GetNotificationRequest().GetFlags();
    ANS_LOGI("OnConsumed Notification key = %{public}s, sortingMap size = %{public}zu, notificationFlag = %{public}s",
        request->GetKey().c_str(), sortingMap->GetKey().size(),
        notificationFlags == nullptr ? "null" : notificationFlags->Dump().c_str());
    ANS_LOGD("OnConsumed Notification info is %{public}s", request->GetNotificationRequest().Dump().c_str());
    
    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("new dataWorker failed");
        return;
    }

    dataWorker->request = request;
    dataWorker->sortingMap = sortingMap;
    dataWorker->env = consumeCallbackInfo_.env;
    dataWorker->ref = consumeCallbackInfo_.ref;
    dataWorker->type = Type::CONSUME;
    napi_acquire_threadsafe_function(tsfn_);
    napi_call_threadsafe_function(tsfn_, dataWorker, napi_tsfn_nonblocking);
    napi_release_threadsafe_function(tsfn_, napi_tsfn_release);
}

void ThreadSafeOnUpdate(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("OnUpdate thread safe start");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("dataWorkerData is nullptr");
        return;
    }
    napi_value result = nullptr;
    napi_handle_scope scope;
    napi_open_handle_scope(dataWorkerData->env, &scope);
    if (scope == nullptr) {
        ANS_LOGE("Scope is null");
        return;
    }
    napi_create_object(dataWorkerData->env, &result);
    if (!Common::SetNotificationSortingMap(dataWorkerData->env, dataWorkerData->sortingMap, result)) {
        ANS_LOGE("Failed to convert data to JS");
    } else {
        Common::SetCallback(dataWorkerData->env, dataWorkerData->ref, result);
    }
    napi_close_handle_scope(dataWorkerData->env, scope);

    delete dataWorkerData;
    dataWorkerData = nullptr;
}

void SubscriberInstance::OnUpdate(const std::shared_ptr<NotificationSortingMap> &sortingMap)
{
    ANS_LOGD("enter");

    if (updateCallbackInfo_.ref == nullptr || updateCallbackInfo_.env == nullptr) {
        ANS_LOGI("update callback or env unset");
        return;
    }

    if (sortingMap == nullptr) {
        ANS_LOGE("sortingMap is null");
        return;
    }
    ANS_LOGI("OnUpdate sortingMap size = %{public}zu", sortingMap->GetKey().size());

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("new dataWorker failed");
        return;
    }

    dataWorker->sortingMap = sortingMap;
    dataWorker->env = updateCallbackInfo_.env;
    dataWorker->ref = updateCallbackInfo_.ref;
    dataWorker->type = Type::UPDATE;

    napi_acquire_threadsafe_function(tsfn_);
    napi_call_threadsafe_function(tsfn_, dataWorker, napi_tsfn_nonblocking);
    napi_release_threadsafe_function(tsfn_, napi_tsfn_release);
}

void ThreadSafeOnConnected(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGD("OnConnected thread safe start");
    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("dataWorkerData is nullptr.");
        return;
    }

    Common::SetCallback(dataWorkerData->env, dataWorkerData->ref, Common::NapiGetNull(dataWorkerData->env));

    delete dataWorkerData;
    dataWorkerData = nullptr;
}

void SubscriberInstance::OnConnected()
{
    ANS_LOGD("enter");

    if (subscribeCallbackInfo_.ref == nullptr || subscribeCallbackInfo_.env == nullptr) {
        ANS_LOGI("subscribe callback or env unset");
        return;
    }

    if (tsfn_ == nullptr) {
        ANS_LOGI("subscribe tsfn is null");
        return;
    }
    
    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("new dataWorker failed");
        return;
    }

    dataWorker->env = subscribeCallbackInfo_.env;
    dataWorker->ref = subscribeCallbackInfo_.ref;
    dataWorker->type = Type::CONNECTED;

    napi_acquire_threadsafe_function(tsfn_);
    napi_call_threadsafe_function(tsfn_, dataWorker, napi_tsfn_nonblocking);
    napi_release_threadsafe_function(tsfn_, napi_tsfn_release);
}

void ThreadSafeOnDisconnected(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("OnDisconnected thread safe start");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("Failed to create dataWorkerData.");
        return;
    }

    Common::SetCallback(dataWorkerData->env, dataWorkerData->ref, Common::NapiGetNull(dataWorkerData->env));
    DelSubscriberInstancesInfo(dataWorkerData->env, dataWorkerData->subscriber);
    delete dataWorkerData;
    dataWorkerData = nullptr;
}

void SubscriberInstance::OnDisconnected()
{
    ANS_LOGD("enter");

    if (unsubscribeCallbackInfo_.ref == nullptr) {
        ANS_LOGI("unsubscribe callback unset");
        return;
    }

    if (tsfn_ == nullptr) {
        ANS_LOGI("unsubscribe tsfn is null");
        return;
    }

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("new dataWorker failed");
        return;
    }

    dataWorker->env = unsubscribeCallbackInfo_.env;
    dataWorker->ref = unsubscribeCallbackInfo_.ref;
    dataWorker->subscriber = std::static_pointer_cast<SubscriberInstance>(shared_from_this());
    dataWorker->type = Type::DIS_CONNECTED;

    napi_acquire_threadsafe_function(tsfn_);
    napi_call_threadsafe_function(tsfn_, dataWorker, napi_tsfn_nonblocking);
    napi_release_threadsafe_function(tsfn_, napi_tsfn_release);
}

void ThreadSafeOnDestroy(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("OnDied thread safe start");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("dataWorkerData is null");
        return;
    }

    Common::SetCallback(
        dataWorkerData->env, dataWorkerData->ref, Common::NapiGetNull(dataWorkerData->env));

    delete dataWorkerData;
    dataWorkerData = nullptr;
}

void SubscriberInstance::OnDied()
{
    ANS_LOGD("enter");

    if (dieCallbackInfo_.ref == nullptr) {
        ANS_LOGE("die callback unset");
        return;
    }

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("new dataWorker failed");
        return;
    }

    dataWorker->env = dieCallbackInfo_.env;
    dataWorker->ref = dieCallbackInfo_.ref;
    dataWorker->type = Type::DIE;

    napi_acquire_threadsafe_function(tsfn_);
    napi_call_threadsafe_function(tsfn_, dataWorker, napi_tsfn_nonblocking);
    napi_release_threadsafe_function(tsfn_, napi_tsfn_release);
}

void ThreadSafeOnDoNotDisturbDateChange(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("OnDoNotDisturbDateChange thread safe start");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("Data worker data is null.");
        return;
    }

    napi_value result = nullptr;
    napi_handle_scope scope;
    napi_open_handle_scope(dataWorkerData->env, &scope);
    if (scope == nullptr) {
        ANS_LOGE("Scope is null");
        return;
    }
    napi_create_object(dataWorkerData->env, &result);

    if (!Common::SetDoNotDisturbDate(dataWorkerData->env, dataWorkerData->date, result)) {
        result = Common::NapiGetNull(dataWorkerData->env);
    }

    Common::SetCallback(dataWorkerData->env, dataWorkerData->ref, result);
    napi_close_handle_scope(dataWorkerData->env, scope);

    delete dataWorkerData;
    dataWorkerData = nullptr;
}

void SubscriberInstance::OnDoNotDisturbDateChange(const std::shared_ptr<NotificationDoNotDisturbDate> &date)
{
    ANS_LOGD("enter");

    onDoNotDisturbChanged(date);

    if (disturbDateCallbackInfo_.ref == nullptr || disturbDateCallbackInfo_.env == nullptr) {
        ANS_LOGI("disturbDateCallbackInfo_ callback or env unset");
        return;
    }

    if (date == nullptr) {
        ANS_LOGE("date is null");
        return;
    }

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("new dataWorker failed");
        return;
    }

    dataWorker->date = *date;
    dataWorker->env = disturbDateCallbackInfo_.env;
    dataWorker->ref = disturbDateCallbackInfo_.ref;
    dataWorker->type = Type::DISTURB_DATE_CHANGE;

    napi_acquire_threadsafe_function(tsfn_);
    napi_call_threadsafe_function(tsfn_, dataWorker, napi_tsfn_nonblocking);
    napi_release_threadsafe_function(tsfn_, napi_tsfn_release);
}


void ThreadSafeOnDoNotDisturbChanged(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("OnDoNotDisturbChanged thread safe start");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("Data worker data is null.");
        return;
    }

    napi_value result = nullptr;
    napi_handle_scope scope;
    napi_open_handle_scope(dataWorkerData->env, &scope);
    napi_create_object(dataWorkerData->env, &result);

    if (!Common::SetDoNotDisturbDate(dataWorkerData->env, dataWorkerData->date, result)) {
        result = Common::NapiGetNull(dataWorkerData->env);
    }

    Common::SetCallback(dataWorkerData->env, dataWorkerData->ref, result);
    napi_close_handle_scope(dataWorkerData->env, scope);

    delete dataWorkerData;
    dataWorkerData = nullptr;
}

void SubscriberInstance::onDoNotDisturbChanged(const std::shared_ptr<NotificationDoNotDisturbDate>& date)
{
    ANS_LOGD("enter");

    if (disturbChangedCallbackInfo_.ref == nullptr || disturbChangedCallbackInfo_.env == nullptr) {
        ANS_LOGE("disturbChangedCallbackInfo_ callback or env unset");
        return;
    }

    if (date == nullptr) {
        ANS_LOGE("date is null");
        return;
    }

    NotificationReceiveDataWorker* dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("new dataWorker failed");
        return;
    }

    dataWorker->date = *date;
    dataWorker->env = disturbChangedCallbackInfo_.env;
    dataWorker->ref = disturbChangedCallbackInfo_.ref;
    dataWorker->type = Type::DISTURB_CHANGED;

    napi_acquire_threadsafe_function(tsfn_);
    napi_call_threadsafe_function(tsfn_, dataWorker, napi_tsfn_nonblocking);
    napi_release_threadsafe_function(tsfn_, napi_tsfn_release);
}

void ThreadSafeOnEnabledNotificationChanged(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("OnEnabledNotificationChanged thread safe start");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("Data worker data is null.");
        return;
    }

    napi_value result = nullptr;
    napi_handle_scope scope;
    napi_open_handle_scope(dataWorkerData->env, &scope);
    if (scope == nullptr) {
        ANS_LOGE("Scope is null");
        return;
    }
    napi_create_object(dataWorkerData->env, &result);

    if (!Common::SetEnabledNotificationCallbackData(dataWorkerData->env, dataWorkerData->callbackData, result)) {
        result = Common::NapiGetNull(dataWorkerData->env);
    }

    Common::SetCallback(dataWorkerData->env, dataWorkerData->ref, result);
    napi_close_handle_scope(dataWorkerData->env, scope);

    delete dataWorkerData;
    dataWorkerData = nullptr;
}

void SubscriberInstance::OnEnabledNotificationChanged(
    const std::shared_ptr<EnabledNotificationCallbackData> &callbackData)
{
    ANS_LOGD("enter");

    if (enabledNotificationCallbackInfo_.ref == nullptr || enabledNotificationCallbackInfo_.env == nullptr) {
        ANS_LOGI("enabledNotificationCallbackInfo_ callback or env unset");
        return;
    }

    if (callbackData == nullptr) {
        ANS_LOGE("callbackData is null");
        return;
    }

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("new dataWorker failed");
        return;
    }

    dataWorker->callbackData = *callbackData;
    dataWorker->env = enabledNotificationCallbackInfo_.env;
    dataWorker->ref = enabledNotificationCallbackInfo_.ref;
    dataWorker->type = Type::ENABLE_NOTIFICATION_CHANGED;

    napi_acquire_threadsafe_function(tsfn_);
    napi_call_threadsafe_function(tsfn_, dataWorker, napi_tsfn_nonblocking);
    napi_release_threadsafe_function(tsfn_, napi_tsfn_release);
}

void ThreadSafeOnBadgeChanged(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("OnBadgeChanged thread safe start");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("dataWorkerData is null");
        return;
    }

    napi_value result = nullptr;
    napi_handle_scope scope;
    napi_open_handle_scope(dataWorkerData->env, &scope);
    if (scope == nullptr) {
        ANS_LOGE("Scope is null");
        return;
    }
    napi_create_object(dataWorkerData->env, &result);

    if (!Common::SetBadgeCallbackData(dataWorkerData->env, dataWorkerData->badge, result)) {
        result = Common::NapiGetNull(dataWorkerData->env);
    }

    Common::SetCallback(dataWorkerData->env, dataWorkerData->ref, result);
    napi_close_handle_scope(dataWorkerData->env, scope);

    delete dataWorkerData;
    dataWorkerData = nullptr;
}

void SubscriberInstance::OnBadgeChanged(
    const std::shared_ptr<BadgeNumberCallbackData> &badgeData)
{
    ANS_LOGD("enter");

    if (setBadgeCallbackInfo_.ref == nullptr || setBadgeCallbackInfo_.env == nullptr) {
        return;
    }

    if (badgeData == nullptr) {
        ANS_LOGE("badgeData is null");
        return;
    }

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("new dataWorker failed");
        return;
    }

    dataWorker->badge = *badgeData;
    dataWorker->env = setBadgeCallbackInfo_.env;
    dataWorker->ref = setBadgeCallbackInfo_.ref;
    dataWorker->type = Type::BADGE_CHANGED;

    napi_acquire_threadsafe_function(tsfn_);
    napi_call_threadsafe_function(tsfn_, dataWorker, napi_tsfn_nonblocking);
    napi_release_threadsafe_function(tsfn_, napi_tsfn_release);
}

void ThreadSafeOnBadgeEnabledChanged(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("OnBadgeEnabledChanged thread safe start.");

    auto dataWorkerData = reinterpret_cast<NotificationReceiveDataWorker *>(data);
    if (dataWorkerData == nullptr) {
        ANS_LOGE("Data worker is null.");
        return;
    }

    napi_value result = nullptr;
    napi_handle_scope scope;
    napi_open_handle_scope(dataWorkerData->env, &scope);
    if (scope == nullptr) {
        ANS_LOGE("Scope is null");
        return;
    }
    napi_create_object(dataWorkerData->env, &result);
    if (!Common::SetEnabledNotificationCallbackData(dataWorkerData->env, dataWorkerData->callbackData, result)) {
        result = Common::NapiGetNull(dataWorkerData->env);
    }

    Common::SetCallback(dataWorkerData->env, dataWorkerData->ref, result);
    napi_close_handle_scope(dataWorkerData->env, scope);

    delete dataWorkerData;
    dataWorkerData = nullptr;
}

void SubscriberInstance::OnBadgeEnabledChanged(
    const sptr<EnabledNotificationCallbackData> &callbackData)
{
    if (setBadgeEnabledCallbackInfo_.ref == nullptr) {
        ANS_LOGE("Set badge enabled callback info is null.");
        return;
    }
    if (callbackData == nullptr) {
        ANS_LOGE("Callback data is null.");
        return;
    }

    NotificationReceiveDataWorker *dataWorker = new (std::nothrow) NotificationReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("Create new data worker failed.");
        return;
    }

    dataWorker->callbackData = *callbackData;
    dataWorker->env = setBadgeEnabledCallbackInfo_.env;
    dataWorker->ref = setBadgeEnabledCallbackInfo_.ref;
    dataWorker->type = Type::BADGE_ENABLED_CHANGED;
    
    napi_acquire_threadsafe_function(tsfn_);
    napi_call_threadsafe_function(tsfn_, dataWorker, napi_tsfn_nonblocking);
    napi_release_threadsafe_function(tsfn_, napi_tsfn_release);
}

void SubscriberInstance::SetThreadSafeFunction(const napi_threadsafe_function &tsfn)
{
    tsfn_ = tsfn;
}

void SubscriberInstance::SetCancelCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    canceCallbackInfo_.env = env;
    canceCallbackInfo_.ref = ref;
}

void SubscriberInstance::SetConsumeCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    consumeCallbackInfo_.env = env;
    consumeCallbackInfo_.ref = ref;
}

void SubscriberInstance::SetUpdateCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    updateCallbackInfo_.env = env;
    updateCallbackInfo_.ref = ref;
}

void SubscriberInstance::SetSubscribeCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    subscribeCallbackInfo_.env = env;
    subscribeCallbackInfo_.ref = ref;
}

void SubscriberInstance::SetUnsubscribeCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    unsubscribeCallbackInfo_.env = env;
    unsubscribeCallbackInfo_.ref = ref;
}

void SubscriberInstance::SetDieCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    dieCallbackInfo_.env = env;
    dieCallbackInfo_.ref = ref;
}

void SubscriberInstance::SetDisturbModeCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    disturbModeCallbackInfo_.env = env;
    disturbModeCallbackInfo_.ref = ref;
}

void SubscriberInstance::SetEnabledNotificationCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    enabledNotificationCallbackInfo_.env = env;
    enabledNotificationCallbackInfo_.ref = ref;
}

void SubscriberInstance::SetDisturbDateCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    disturbDateCallbackInfo_.env = env;
    disturbDateCallbackInfo_.ref = ref;
}

void SubscriberInstance::SetDisturbChangedCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    disturbChangedCallbackInfo_.env = env;
    disturbChangedCallbackInfo_.ref = ref;
}

void SubscriberInstance::SetBadgeCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    setBadgeCallbackInfo_.env = env;
    setBadgeCallbackInfo_.ref = ref;
}


void SubscriberInstance::SetBadgeEnabledCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    setBadgeEnabledCallbackInfo_.env = env;
    setBadgeEnabledCallbackInfo_.ref = ref;
}

void SubscriberInstance::SetBatchCancelCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    batchCancelCallbackInfo_.env = env;
    batchCancelCallbackInfo_.ref = ref;
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

bool HasNotificationSubscriber(const napi_env &env, const napi_value &value, SubscriberInstancesInfo &subscriberInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
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
    ANS_LOGD("ThreadFinished");
}

void ThreadSafeCommon(napi_env env, napi_value jsCallback, void* context, void* data)
{
    ANS_LOGI("common thread safe start");
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
}

napi_value GetNotificationSubscriber(
    const napi_env &env, const napi_value &value, SubscriberInstancesInfo &subscriberInfo)
{
    ANS_LOGD("enter");
    bool hasProperty = false;
    napi_valuetype valuetype = napi_undefined;
    napi_ref result = nullptr;

    subscriberInfo.subscriber = std::make_shared<SubscriberInstance>();
    if (subscriberInfo.subscriber == nullptr) {
        ANS_LOGE("subscriber is null");
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
    ANS_LOGD("enter");
    if (subscriberInfo.ref == nullptr) {
        ANS_LOGE("subscriberInfo.ref is null");
        return false;
    }
    if (subscriberInfo.subscriber == nullptr) {
        ANS_LOGE("subscriberInfo.subscriber is null");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    subscriberInstances_.emplace_back(subscriberInfo);

    return true;
}

bool DelSubscriberInstancesInfo(const napi_env &env, const std::shared_ptr<SubscriberInstance> subscriber)
{
    ANS_LOGD("enter");
    if (subscriber == nullptr) {
        ANS_LOGE("subscriber is null");
        return false;
    }
    std::lock_guard<std::mutex> lock(delMutex_);
    auto iter = std::find(DeletingSubscriber.begin(), DeletingSubscriber.end(), subscriber);
    if (iter != DeletingSubscriber.end()) {
        DeletingSubscriber.erase(iter);
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto it = subscriberInstances_.begin(); it != subscriberInstances_.end(); ++it) {
            if ((*it).subscriber == subscriber) {
                if ((*it).ref != nullptr) {
                    napi_delete_reference(env, (*it).ref);
                }
                subscriberInstances_.erase(it);
                return true;
            }
        }
    }
    return false;
}

napi_value ParseParameters(const napi_env &env, const napi_callback_info &info,
    NotificationSubscribeInfo &subscriberInfo, std::shared_ptr<SubscriberInstance> &subscriber, napi_ref &callback)
{
    ANS_LOGD("enter");

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
    ANS_LOGD("enter");

    napi_ref callback = nullptr;
    std::shared_ptr<SubscriberInstance> objectInfo = nullptr;
    NotificationSubscribeInfo subscriberInfo;
    if (ParseParameters(env, info, subscriberInfo, objectInfo, callback) == nullptr) {
        ANS_LOGD("ParseParameters is nullptr.");
        return Common::NapiGetUndefined(env);
    }

    AsyncCallbackInfoSubscribe *asynccallbackinfo = new (std::nothrow) AsyncCallbackInfoSubscribe {
        .env = env, .asyncWork = nullptr, .objectInfo = objectInfo, .subscriberInfo = subscriberInfo
    };
    if (!asynccallbackinfo) {
        ANS_LOGD("Asynccallbackinfo is nullptr.");
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
                    OHOS::Notification::NotificationSubscribeInfo subscribeInfo;
                    subscribeInfo.AddAppNames(asynccallbackinfo->subscriberInfo.bundleNames);
                    subscribeInfo.AddAppUserId(asynccallbackinfo->subscriberInfo.userId);
                    asynccallbackinfo->info.errorCode =
                        NotificationHelper::SubscribeNotification(*(asynccallbackinfo->objectInfo), subscribeInfo);
                } else {
                    ANS_LOGD("SubscribeNotification execute.");
                    asynccallbackinfo->info.errorCode =
                        NotificationHelper::SubscribeNotification(*(asynccallbackinfo->objectInfo));
                }
            }
        },
        [](napi_env env, napi_status status, void *data) {
            ANS_LOGD("Subscribe work complete.");
            if (!data) {
                ANS_LOGE("Invalid asynccallbackinfo!");
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

    napi_queue_async_work_with_qos(env, asynccallbackinfo->asyncWork, napi_qos_user_initiated);

    if (asynccallbackinfo->info.isCallback) {
        ANS_LOGD("subscribe callback is nullptr.");
        return Common::NapiGetNull(env);
    } else {
        return promise;
    }
}

bool AddDeletingSubscriber(std::shared_ptr<SubscriberInstance> subscriber)
{
    std::lock_guard<std::mutex> lock(delMutex_);
    auto iter = std::find(DeletingSubscriber.begin(), DeletingSubscriber.end(), subscriber);
    if (iter != DeletingSubscriber.end()) {
        return false;
    }

    DeletingSubscriber.push_back(subscriber);
    return true;
}

void DelDeletingSubscriber(std::shared_ptr<SubscriberInstance> subscriber)
{
    std::lock_guard<std::mutex> lock(delMutex_);
    auto iter = std::find(DeletingSubscriber.begin(), DeletingSubscriber.end(), subscriber);
    if (iter != DeletingSubscriber.end()) {
        DeletingSubscriber.erase(iter);
    }
}
}  // namespace NotificationNapi
}  // namespace OHOS