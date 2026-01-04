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
#include "ani_sync_config.h"

#include "notification_helper.h"
#include "ans_log_wrapper.h"
#include "sts_throw_erro.h"
#include "sts_common.h"
#include "sts_bundle_option.h"
#include "sts_notification_manager.h"

namespace OHOS {
namespace NotificationManagerSts {
using namespace arkts::concurrency_helpers;
const char KEY_NAME[] = "AGGREGATE_CONFIG";
const char RING_LIST_KEY_NAME[] = "RING_TRUSTLIST_PKG";
const char CTRL_LIST_KEY_NAME[] = "NOTIFICATION_CTL_LIST_PKG";
const char PRIORITY_RULE_CONFIG_KEY_NAME[] = "notificationRuleConfig";
const char CAMPAIGN_NOTIFICATION_SWITCH_LIST_PKG[] = "CAMPAIGN_NOTIFICATION_SWITCH_LIST_PKG";
const char HEALTH_BUNDLE_WHITE_LIST[]  = "HEALTH_BUNDLE_WHITE_LIST";

void DeleteCallBackInfoWithoutPromise(ani_env* env, AsyncCallbackConfigInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackConfigInfo Without Promise");
    if (!asyncCallbackInfo) {
        return;
    }
    if (asyncCallbackInfo->info.callback != nullptr) {
        ANS_LOGD("Delete callback reference");
        env->GlobalReference_Delete(asyncCallbackInfo->info.callback);
    }
    if (asyncCallbackInfo->asyncWork != nullptr) {
        ANS_LOGD("DeleteAsyncWork");
        DeleteAsyncWork(env, asyncCallbackInfo->asyncWork);
        asyncCallbackInfo->asyncWork = nullptr;
    }
    delete asyncCallbackInfo;
    asyncCallbackInfo = nullptr;
}

void DeleteCallBackInfo(ani_env* env, AsyncCallbackConfigInfo* asyncCallbackInfo)
{
    ANS_LOGD("Delete AsyncCallbackConfigInfo");
    if (!asyncCallbackInfo) {
        return;
    }
    if (asyncCallbackInfo->info.resolve != nullptr) {
        ANS_LOGD("Delete resolve reference");
        env->GlobalReference_Delete(reinterpret_cast<ani_ref>(asyncCallbackInfo->info.resolve));
    }
    DeleteCallBackInfoWithoutPromise(env, asyncCallbackInfo);
}

bool SetCallbackObject(ani_env* env, ani_object callback, AsyncCallbackConfigInfo* asyncCallbackInfo)
{
    if (!NotificationSts::IsUndefine(env, callback)) {
        ani_ref globalRef;
        if (env->GlobalReference_Create(static_cast<ani_ref>(callback), &globalRef) != ANI_OK) {
            NotificationSts::ThrowInternerErrorWithLogE(env, "create callback ref failed");
            return false;
        }
        asyncCallbackInfo->info.callback = globalRef;
    }
    return true;
}

bool CheckCompleteEnvironment(ani_env **envCurr, AsyncCallbackConfigInfo* asyncCallbackInfo)
{
    if (asyncCallbackInfo->vm->GetEnv(ANI_VERSION_1, envCurr) != ANI_OK || envCurr == nullptr) {
        ANS_LOGE("GetEnv failed");
        return false;
    }
    if (asyncCallbackInfo->info.returnCode != ERR_OK) {
        ANS_LOGE("return ErrCode: %{public}d", asyncCallbackInfo->info.returnCode);
        NotificationSts::CreateReturnData(*envCurr, asyncCallbackInfo->info);
        DeleteCallBackInfoWithoutPromise(*envCurr, asyncCallbackInfo);
        return false;
    }
    return true;
}

void HandleConfigFunctionCallbackComplete(ani_env* env, WorkStatus status, void* data)
{
    auto asyncCallbackInfo = static_cast<AsyncCallbackConfigInfo*>(data);
    if (!asyncCallbackInfo) {
        ANS_LOGE("asyncCallbackInfo  is null");
        return;
    }
    ani_env *envCurr = nullptr;
    if (!CheckCompleteEnvironment(&envCurr, asyncCallbackInfo)) {
        return;
    }
    asyncCallbackInfo->info.result = OHOS::NotificationSts::CreateInt(envCurr, asyncCallbackInfo->result);
    NotificationSts::CreateReturnData(envCurr, asyncCallbackInfo->info);
    DeleteCallBackInfoWithoutPromise(envCurr, asyncCallbackInfo);
}

bool ParsePraramForAdditionalConfig(ani_env *env,
    ani_string key, ani_string value, AsyncCallbackConfigInfo* asyncCallbackInfo)
{
    std::string tempKey;
    if (NotificationSts::GetStringByAniString(env, key, tempKey) != ANI_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Parse key failed");
        asyncCallbackInfo->result = RESULT_FAILED;
        return false;
    }
    std::string keyStr = NotificationSts::GetResizeStr(tempKey, NotificationSts::STR_MAX_SIZE);
    if (keyStr.empty() || (keyStr != KEY_NAME && keyStr != RING_LIST_KEY_NAME &&
        keyStr != CTRL_LIST_KEY_NAME && keyStr != HEALTH_BUNDLE_WHITE_LIST &&
        keyStr != PRIORITY_RULE_CONFIG_KEY_NAME &&
        keyStr != CAMPAIGN_NOTIFICATION_SWITCH_LIST_PKG)) {
        ANS_LOGW("Argument param error. not allow key: %{public}s.", keyStr.c_str());
        return false;
    }
    std::string tempValue;
    if (NotificationSts::GetStringByAniString(env, value, tempValue) != ANI_OK) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "Parse value failed");
        asyncCallbackInfo->result = RESULT_FAILED;
        return false;
    }
    std::string valueStr = NotificationSts::GetResizeStr(tempValue, NotificationSts::LONG_LONG_STR_MAX_SIZE);
    asyncCallbackInfo->configValue = valueStr;
    asyncCallbackInfo->configkey = keyStr;
    return true;
}

ani_object AniSetAdditionalConfig(ani_env *env, ani_string key, ani_string value, ani_object callback)
{
    ANS_LOGD("AniSetAdditionalConfig called");
    auto asyncCallbackInfo = new (std::nothrow)AsyncCallbackConfigInfo{.asyncWork = nullptr};
    if (!asyncCallbackInfo) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "asyncCallbackInfo is nullptr");
        return nullptr;
    }
    if (!ParsePraramForAdditionalConfig(env, key, value, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (!SetCallbackObject(env, callback, asyncCallbackInfo)) {
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    ani_object promise;
    NotificationSts::PaddingCallbackPromiseInfo(env, asyncCallbackInfo->info.callback,
        asyncCallbackInfo->info, promise);
    env->GetVM(&asyncCallbackInfo->vm);
    WorkStatus status = CreateAsyncWork(env,
        [](ani_env* env, void* data) {
            auto asyncCallbackInfo = static_cast<AsyncCallbackConfigInfo*>(data);
            if (asyncCallbackInfo) {
                if (asyncCallbackInfo->result != ERR_OK) {
                    asyncCallbackInfo->info.returnCode = Notification::NotificationHelper::SetAdditionConfig(
                        asyncCallbackInfo->configkey, asyncCallbackInfo->configValue);
                    asyncCallbackInfo->result = ERR_OK;
                }
            }
        },
        HandleConfigFunctionCallbackComplete, (void*)asyncCallbackInfo, &(asyncCallbackInfo->asyncWork));
    if (status != WorkStatus::OK || WorkStatus::OK != QueueAsyncWork(env, asyncCallbackInfo->asyncWork)) {
        NotificationSts::ThrowInternerErrorWithLogE(env, "CreateAsyncWork or QueueAsyncWork failed");
        DeleteCallBackInfo(env, asyncCallbackInfo);
        return nullptr;
    }
    if (asyncCallbackInfo->info.callback == nullptr) {
        return promise;
    }
    return nullptr;
}
} // namespace NotificationManagerSts
} // namespace OHOS