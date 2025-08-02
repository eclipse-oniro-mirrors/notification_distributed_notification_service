/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "js_ans_dialog_callback.h"

#include <uv.h>

#include "ians_dialog_callback.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"

namespace OHOS {

namespace NotificationNapi {
bool JsAnsDialogCallback::Init(napi_env env,
    AsyncCallbackInfoIsEnable* callbackInfo,
    JsAnsDialogCallbackComplete complete)
{
    ANS_LOGD("enter");
    if (env == nullptr || callbackInfo == nullptr || complete == nullptr) {
        ANS_LOGE("invalid data");
        return false;
    }
    env_ = env;
    callbackInfo_ = callbackInfo;
    complete_ = complete;
    return true;
}

int32_t JsAnsDialogCallback::GetErrCodeFromStatus(EnabledDialogStatus status)
{
    switch (static_cast<EnabledDialogStatus>(status)) {
        case EnabledDialogStatus::ALLOW_CLICKED:
            return ERR_OK;
        case EnabledDialogStatus::DENY_CLICKED:
            return ERR_ANS_NOT_ALLOWED;
        case EnabledDialogStatus::CRASHED:
            return ERROR_INTERNAL_ERROR;
        default:
            return ERROR_INTERNAL_ERROR;
    }
    return ERROR_INTERNAL_ERROR;
}

void JsAnsDialogCallback::ProcessDialogStatusChanged(const DialogStatusData& data)
{
    ANS_LOGD("enter");
    std::unique_ptr<AsyncCallbackInfoIsEnable> callbackInfo(callbackInfo_);
    if (env_ == nullptr || callbackInfo == nullptr || complete_ == nullptr) {
        ANS_LOGE("invalid data");
        return;
    }

    callbackInfo->info.errorCode = JsAnsDialogCallback::GetErrCodeFromStatus(
        static_cast<EnabledDialogStatus>(data.GetStatus()));

    uv_loop_s* loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        ANS_LOGE("loop is nullptr");
        return;
    }

    auto work = std::make_unique<uv_work_t>();
    struct WorkData {
        decltype(env_) env = nullptr;
        decltype(callbackInfo_) callbackInfo = nullptr;
        decltype(complete_) complete = nullptr;
    };
    auto workData = std::make_unique<WorkData>();
    workData->env = env_;
    workData->callbackInfo = callbackInfo_;
    workData->complete = complete_;

    work->data = static_cast<void*>(workData.get());
    auto jsCb = [](uv_work_t* work, int status) {
        ANS_LOGD("enter");
        std::unique_ptr<uv_work_t> workSP(work);
        if (work == nullptr || work->data == nullptr) {
            ANS_LOGE("invalid data");
            return;
        }
        auto* data = static_cast<WorkData*>(work->data);
        std::unique_ptr<WorkData> dataSP(data);
        std::unique_ptr<AsyncCallbackInfoIsEnable> callbackInfoSP(data->callbackInfo);
        if (data->env == nullptr ||
            data->callbackInfo == nullptr ||
            data->complete == nullptr) {
            return;
        }
        auto* callbackInfoPtr = callbackInfoSP.release();
        data->complete(data->env, static_cast<void*>(callbackInfoPtr));
    };

    int ret = uv_queue_work_with_qos(loop,
        work.get(),
        [](uv_work_t *work) {},
        jsCb,
        uv_qos_user_initiated);
    if (ret != 0) {
        ANS_LOGE("uv_queue_work failed");
        return;
    }
    callbackInfo.release();
    workData.release();
    work.release();
}
} // namespace NotificationNapi
} // namespace OHOS
