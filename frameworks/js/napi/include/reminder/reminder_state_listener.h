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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_REMINDER_REMINDER_STATE_LISTEN_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_INCLUDE_REMINDER_REMINDER_STATE_LISTEN_H

#include "reminder_state_callback.h"

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "native_engine/native_engine.h"

namespace OHOS::ReminderAgentNapi {
using OnReminderStateCb = std::function<void(napi_env, napi_value, std::vector<Notification::ReminderState>)>;
class JsReminderStateCallback : public Notification::ReminderStateCallback {
public:
    JsReminderStateCallback(napi_env env, napi_value callbackObj, OnReminderStateCb callback);
    ~JsReminderStateCallback() = default;

    void OnReminderState(const std::vector<Notification::ReminderState>& states) override;

private:
    static void ThreadSafeCallBack(napi_env env, napi_value jsCb, void* context, void* data);

private:
    napi_threadsafe_function threadSafeFunction_ {nullptr};
    napi_env napiEnv_ {nullptr};
    OnReminderStateCb reminderStateCb_ {nullptr};
    std::shared_ptr<NativeReference> callbackRef_ {nullptr};
};

class JsReminderStateListener {
public:
    struct ReminderStateCbInfo {
        explicit ReminderStateCbInfo(napi_env env)
            : nativeEnv(env) {}
        ~ReminderStateCbInfo()
        {
            if (nativeEnv) {
                if (callback) {
                    napi_delete_reference(nativeEnv, callback);
                    callback = nullptr;
                }
                if (asyncWork) {
                    napi_delete_async_work(nativeEnv, asyncWork);
                    asyncWork = nullptr;
                }
            }
        }
        napi_ref callback {nullptr};
        napi_async_work asyncWork {nullptr};
        napi_deferred deferred {nullptr};
        napi_env nativeEnv {nullptr};
        std::vector<Notification::ReminderState> states;
    };

public:
    using CallBackPair = std::pair<std::unique_ptr<NativeReference>, sptr<JsReminderStateCallback>>;

    static JsReminderStateListener& GetInstance();

    napi_value RegisterReminderStateCallback(napi_env env, napi_callback_info info);
    napi_value UnRegisterReminderStateCallback(napi_env env, napi_callback_info info);

    void OnReminderState(napi_env env, napi_value callbackObj, const std::vector<Notification::ReminderState>& states);

private:
    JsReminderStateListener() = default;
    ~JsReminderStateListener();
    JsReminderStateListener(const JsReminderStateListener&) = delete;
    JsReminderStateListener& operator=(const JsReminderStateListener&) = delete;

    bool CheckCallbackParam(napi_env env, napi_callback_info info,
        napi_value* jsCallback, const bool isRegister);

    static void CompleteCb(napi_env env, ReminderStateCbInfo* info);

    std::mutex jsCallBackListMutex_;
    std::list<CallBackPair> jsCallBackList_;
};
}  // namespace OHOS::ReminderAgentNapi

#endif