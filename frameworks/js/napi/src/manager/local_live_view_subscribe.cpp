/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "local_live_view_subscribe.h"
#include "notification_button_option.h"
#include "ans_inner_errors.h"
#include <mutex>
#include <uv.h>

namespace OHOS {
namespace NotificationNapi {
const int32_t SUBSRIBE_MAX_PARA = 2;
const std::string RESPONSE = "onResponse";

struct LocalLiveViewReceiveDataWorker {
    napi_env env = nullptr;
    napi_ref ref = nullptr;
    int32_t notificationId;
    sptr<NotificationButtonOption> buttonOption;
    LocalLiveViewSubscriberInstance *subscriber = nullptr;
};

LocalLiveViewSubscriberInstance::LocalLiveViewSubscriberInstance()
{}

LocalLiveViewSubscriberInstance::~LocalLiveViewSubscriberInstance()
{
    if (responseCallbackInfo_.ref != nullptr) {
        napi_delete_reference(responseCallbackInfo_.env, responseCallbackInfo_.ref);
    }
}

void LocalLiveViewSubscriberInstance::OnDied()
{
    ANS_LOGD("called");
}

void LocalLiveViewSubscriberInstance::OnConnected()
{
    ANS_LOGD("called");
}

void LocalLiveViewSubscriberInstance::OnDisconnected()
{
    ANS_LOGD("called");
}

void UvQueueWorkOnResponse(uv_work_t *work, int status)
{
    ANS_LOGD("called");

    if (work == nullptr) {
        ANS_LOGE("null work");
        return;
    }

    auto dataWorkerData = reinterpret_cast<LocalLiveViewReceiveDataWorker *>(work->data);
    if (dataWorkerData == nullptr) {
        ANS_LOGD("null dataWorkerData");
        delete work;
        work = nullptr;
        return;
    }
    napi_value buttonOption = nullptr;
    napi_value buttonName = nullptr;
    napi_handle_scope scope;
    napi_value notificationId = nullptr;
    napi_open_handle_scope(dataWorkerData->env, &scope);
    if (scope == nullptr) {
        ANS_LOGE("null scope");
        return;
    }

    // notificationId: number
    napi_create_int32(dataWorkerData->env, dataWorkerData->notificationId, &notificationId);

    napi_create_object(dataWorkerData->env, &buttonOption);
    napi_create_string_utf8(dataWorkerData->env, dataWorkerData->buttonOption->GetButtonName().c_str(),
        NAPI_AUTO_LENGTH, &buttonName);
    napi_set_named_property(dataWorkerData->env, buttonOption, "buttonName", buttonName);

    Common::SetCallbackArg2(dataWorkerData->env, dataWorkerData->ref, notificationId, buttonOption);
    napi_close_handle_scope(dataWorkerData->env, scope);

    delete dataWorkerData;
    dataWorkerData = nullptr;
    delete work;
}

void LocalLiveViewSubscriberInstance::OnResponse(int32_t notificationId, sptr<NotificationButtonOption> buttonOption)
{
    ANS_LOGD("called");
    
    if (responseCallbackInfo_.ref == nullptr) {
        ANS_LOGE("null ref");
        return;
    }

    if (buttonOption == nullptr) {
        ANS_LOGE("null buttonOption");
        return;
    }

    ANS_LOGI("id = %{public}d", notificationId);
    ANS_LOGI("button = %{public}s", buttonOption->GetButtonName().c_str());

    uv_loop_s *loop = nullptr;
    napi_get_uv_event_loop(responseCallbackInfo_.env, &loop);
    if (loop == nullptr) {
        ANS_LOGE("null loop");
        return;
    }

    LocalLiveViewReceiveDataWorker *dataWorker = new (std::nothrow) LocalLiveViewReceiveDataWorker();
    if (dataWorker == nullptr) {
        ANS_LOGE("null dataWorker");
        return;
    }

    dataWorker->notificationId = notificationId;
    dataWorker->buttonOption = buttonOption;
    dataWorker->env = responseCallbackInfo_.env;
    dataWorker->ref = responseCallbackInfo_.ref;

    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        ANS_LOGE("null work");
        delete dataWorker;
        dataWorker = nullptr;
        return;
    }

    work->data = reinterpret_cast<void *>(dataWorker);

    int ret = uv_queue_work_with_qos(loop, work, [](uv_work_t *work) {},
        UvQueueWorkOnResponse, uv_qos_user_initiated);
    if (ret != 0) {
        delete dataWorker;
        dataWorker = nullptr;
        delete work;
        work = nullptr;
    }
}

void LocalLiveViewSubscriberInstance::SetResponseCallbackInfo(const napi_env &env, const napi_ref &ref)
{
    responseCallbackInfo_.env = env;
    responseCallbackInfo_.ref = ref;
}

void LocalLiveViewSubscriberInstance::SetCallbackInfo(const napi_env &env, const std::string &type, const napi_ref &ref)
{
    if (type == RESPONSE) {
        SetResponseCallbackInfo(env, ref);
    } else {
        ANS_LOGW("type is error");
    }
}

bool HasNotificationSubscriber(const napi_env &env, const napi_value &value,
    LocalLiveViewSubscriberInstancesInfo &subscriberInfo)
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

napi_value GetNotificationSubscriber(
    const napi_env &env, const napi_value &value, LocalLiveViewSubscriberInstancesInfo &subscriberInfo)
{
    ANS_LOGD("called");
    bool hasProperty = false;
    napi_valuetype valuetype = napi_undefined;
    napi_ref result = nullptr;

    subscriberInfo.subscriber = new (std::nothrow) LocalLiveViewSubscriberInstance();
    if (subscriberInfo.subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return nullptr;
    }

    napi_create_reference(env, value, 1, &subscriberInfo.ref);

    // onResponse?
    NAPI_CALL(env, napi_has_named_property(env, value, "onResponse", &hasProperty));
    if (hasProperty) {
        napi_value onResponse = nullptr;
        napi_get_named_property(env, value, "onResponse", &onResponse);
        NAPI_CALL(env, napi_typeof(env, onResponse, &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Wrong argument type. Function expected.");
            std::string msg = "Incorrect parameter types.The type of param must be function.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_create_reference(env, onResponse, 1, &result);
        subscriberInfo.subscriber->SetCallbackInfo(env, RESPONSE, result);
    }
    
    return Common::NapiGetNull(env);
}

bool AddSubscriberInstancesInfo(const napi_env &env, const LocalLiveViewSubscriberInstancesInfo &subscriberInfo)
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
    std::lock_guard<std::mutex> lock(mutex_);
    subscriberInstances_.emplace_back(subscriberInfo);

    return true;
}

bool DelSubscriberInstancesInfo(const napi_env &env, const LocalLiveViewSubscriberInstance *subscriber)
{
    ANS_LOGD("called");
    if (subscriber == nullptr) {
        ANS_LOGE("null subscriber");
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = subscriberInstances_.begin(); it != subscriberInstances_.end(); ++it) {
        if ((*it).subscriber == subscriber) {
            if ((*it).ref != nullptr) {
                napi_delete_reference(env, (*it).ref);
            }
            DelDeletingSubscriber((*it).subscriber);
            delete (*it).subscriber;
            (*it).subscriber = nullptr;
            subscriberInstances_.erase(it);
            return true;
        }
    }
    return false;
}
napi_value ParseParameters(const napi_env &env, const napi_callback_info &info,
    LocalLiveViewSubscriberInstance *&subscriber, napi_ref &callback)
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

    // argv[0]:LocalLiveViewButton
    NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
    if (valuetype != napi_object) {
        ANS_LOGE("Wrong argument type for arg0. LocalLiveViewButton object expected.");
        std::string msg = "Incorrect parameter types.The type of param must be LocalLiveViewButton.";
        Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
        return nullptr;
    }

    LocalLiveViewSubscriberInstancesInfo subscriberInstancesInfo;
    if (!HasNotificationSubscriber(env, argv[PARAM0], subscriberInstancesInfo)) {
        if (GetNotificationSubscriber(env, argv[PARAM0], subscriberInstancesInfo) == nullptr) {
            ANS_LOGE("LocalLiveViewButton parse failed");
            Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
            if (subscriberInstancesInfo.subscriber) {
                delete subscriberInstancesInfo.subscriber;
                subscriberInstancesInfo.subscriber = nullptr;
            }
            return nullptr;
        }
        if (!AddSubscriberInstancesInfo(env, subscriberInstancesInfo)) {
            ANS_LOGE("AddSubscriberInstancesInfo add failed");
            Common::NapiThrow(env, ERROR_PARAM_INVALID, PARAMETER_VERIFICATION_FAILED);
            if (subscriberInstancesInfo.subscriber) {
                delete subscriberInstancesInfo.subscriber;
                subscriberInstancesInfo.subscriber = nullptr;
            }
            return nullptr;
        }
    }
    subscriber = subscriberInstancesInfo.subscriber;

    // argv[1]:callback
    if (argc >= SUBSRIBE_MAX_PARA) {
        NAPI_CALL(env, napi_typeof(env, argv[PARAM1], &valuetype));
        if (valuetype != napi_function) {
            ANS_LOGE("Callback is not function enforce promise.");
            return Common::NapiGetNull(env);
        }
        napi_create_reference(env, argv[PARAM1], 1, &callback);
    }

    return Common::NapiGetNull(env);
}

bool AddDeletingSubscriber(LocalLiveViewSubscriberInstance *subscriber)
{
    std::lock_guard<std::mutex> lock(delMutex_);
    auto iter = std::find(DeletingSubscriber.begin(), DeletingSubscriber.end(), subscriber);
    if (iter != DeletingSubscriber.end()) {
        return false;
    }

    DeletingSubscriber.push_back(subscriber);
    return true;
}

void DelDeletingSubscriber(LocalLiveViewSubscriberInstance *subscriber)
{
    std::lock_guard<std::mutex> lock(delMutex_);
    auto iter = std::find(DeletingSubscriber.begin(), DeletingSubscriber.end(), subscriber);
    if (iter != DeletingSubscriber.end()) {
        DeletingSubscriber.erase(iter);
    }
}

}  // namespace NotificationNapi
}  // namespace OHOS
