/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "common.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi_common.h"
#include "napi_common_util.h"
#include "notification_action_button.h"
#include "notification_capsule.h"
#include "notification_constant.h"
#include "notification_local_live_view_content.h"
#include "notification_progress.h"
#include "notification_time.h"
#include "pixel_map_napi.h"

namespace OHOS {
namespace NotificationNapi {
napi_value Common::SetNotificationByDistributedOptions(
    const napi_env &env, const OHOS::Notification::Notification *notification, napi_value &result)
{
    ANS_LOGD("enter");
    if (notification == nullptr) {
        ANS_LOGE("notification is nullptr");
        return NapiGetBoolean(env, false);
    }

    NotificationDistributedOptions options = notification->GetNotificationRequest().GetNotificationDistributedOptions();
    napi_value value = nullptr;
    // isDistributed?: boolean
    if (notification->GetDeviceId().empty()) {
        napi_get_boolean(env, false, &value);
    } else {
        napi_get_boolean(env, options.IsDistributed(), &value);
    }
    napi_set_named_property(env, result, "isDistributed", value);

    // supportDisplayDevices?: Array<string>
    uint32_t count = 0;
    napi_value arrSupportDisplayDevices = nullptr;
    napi_create_array(env, &arrSupportDisplayDevices);
    std::vector<std::string> displayDevices = options.GetDevicesSupportDisplay();
    for (auto vec : displayDevices) {
        napi_value vecValue = nullptr;
        ANS_LOGI("supportDisplayDevices = %{public}s", vec.c_str());
        napi_create_string_utf8(env, vec.c_str(), NAPI_AUTO_LENGTH, &vecValue);
        napi_set_element(env, arrSupportDisplayDevices, count, vecValue);
        count++;
    }
    napi_set_named_property(env, result, "supportDisplayDevices", arrSupportDisplayDevices);

    // supportOperateDevices?: Array<string>
    count = 0;
    napi_value arrSupportOperateDevices = nullptr;
    napi_create_array(env, &arrSupportOperateDevices);
    std::vector<std::string> operateDevices = options.GetDevicesSupportOperate();
    for (auto vec : operateDevices) {
        napi_value vecValue = nullptr;
        ANS_LOGI("supportOperateDevices  = %{public}s", vec.c_str());
        napi_create_string_utf8(env, vec.c_str(), NAPI_AUTO_LENGTH, &vecValue);
        napi_set_element(env, arrSupportOperateDevices, count, vecValue);
        count++;
    }
    napi_set_named_property(env, result, "supportOperateDevices", arrSupportOperateDevices);

    // readonly remindType?: number
    enum DeviceRemindType outType = DeviceRemindType::IDLE_DONOT_REMIND;
    if (!AnsEnumUtil::DeviceRemindTypeCToJS(notification->GetRemindType(), outType)) {
        return NapiGetBoolean(env, false);
    }
    napi_create_int32(env, static_cast<int32_t>(outType), &value);
    napi_set_named_property(env, result, "remindType", value);

    return NapiGetBoolean(env, true);
}

napi_value Common::SetNotification(
    const napi_env &env, const OHOS::Notification::Notification *notification, napi_value &result)
{
    ANS_LOGD("enter");

    if (notification == nullptr) {
        ANS_LOGE("notification is nullptr");
        return NapiGetBoolean(env, false);
    }
    napi_value value = nullptr;
    NotificationRequest request = notification->GetNotificationRequest();
    if (!SetNotificationRequest(env, &request, result)) {
        return NapiGetBoolean(env, false);
    }

    // hashCode?: string
    napi_create_string_utf8(env, notification->GetKey().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "hashCode", value);

    // isFloatingIcon ?: boolean
    napi_get_boolean(env, notification->IsFloatingIcon(), &value);
    napi_set_named_property(env, result, "isFloatingIcon", value);

    // readonly creatorBundleName?: string
    napi_create_string_utf8(
        env, notification->GetBundleName().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "creatorBundleName", value);

    // readonly creatorUid?: number
    napi_create_int32(env, notification->GetNotificationRequest().GetOwnerUid(), &value);
    napi_set_named_property(env, result, "creatorUid", value);

    // readonly creatorUserId?: number
    napi_create_int32(env, notification->GetRecvUserId(), &value);
    napi_set_named_property(env, result, "creatorUserId", value);

    // readonly creatorInstanceKey?: number
    napi_create_int32(env, -1, &value);
    napi_set_named_property(env, result, "creatorInstanceKey", value);

    // readonly creatorPid?: number
    napi_create_int32(env, notification->GetPid(), &value);
    napi_set_named_property(env, result, "creatorPid", value);

    // distributedOption?:DistributedOptions
    napi_value distributedResult = nullptr;
    napi_create_object(env, &distributedResult);
    if (!SetNotificationByDistributedOptions(env, notification, distributedResult)) {
        return NapiGetBoolean(env, false);
    }
    napi_set_named_property(env, result, "distributedOption", distributedResult);

    // readonly isRemoveAllowed?: boolean
    napi_get_boolean(env, notification->IsRemoveAllowed(), &value);
    napi_set_named_property(env, result, "isRemoveAllowed", value);

    // readonly source?: number
    SourceType sourceType = SourceType::TYPE_NORMAL;
    if (!AnsEnumUtil::SourceTypeCToJS(notification->GetSourceType(), sourceType)) {
        return NapiGetBoolean(env, false);
    }
    napi_create_int32(env, static_cast<int32_t>(sourceType), &value);
    napi_set_named_property(env, result, "source", value);

    // readonly deviceId?: string
    napi_create_string_utf8(env, notification->GetDeviceId().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "deviceId", value);

    // notificationControlFlags?: number
    napi_create_int32(env, notification->GetNotificationRequest().GetNotificationControlFlags(), &value);
    napi_set_named_property(env, result, "notificationControlFlags", value);

    return NapiGetBoolean(env, true);
}


napi_value Common::GetNotificationRequestDistributedOptions(const napi_env &env,
    const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");
    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;

    // distributedOption?: DistributedOptions
    NAPI_CALL(env, napi_has_named_property(env, value, "distributedOption", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "distributedOption", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_object) {
            ANS_LOGE("Wrong argument type. Object expected.");
            std::string msg = "Incorrect parameter types. The type of distributedOption must be object.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }

        // isDistributed?: boolean
        if (GetNotificationIsDistributed(env, result, request) == nullptr) {
            return nullptr;
        }

        // supportDisplayDevices?: Array<string>
        if (GetNotificationSupportDisplayDevices(env, result, request) == nullptr) {
            return nullptr;
        }

        // supportOperateDevices?: Array<string>
        if (GetNotificationSupportOperateDevices(env, result, request) == nullptr) {
            return nullptr;
        }
    }

    return NapiGetNull(env);
}

napi_value Common::GetNotificationIsDistributed(
    const napi_env &env, const napi_value &value, NotificationRequest &request)
{
    ANS_LOGD("enter");

    napi_valuetype valuetype = napi_undefined;
    napi_value result = nullptr;
    bool hasProperty = false;
    bool isDistributed = false;

    NAPI_CALL(env, napi_has_named_property(env, value, "isDistributed", &hasProperty));
    if (hasProperty) {
        napi_get_named_property(env, value, "isDistributed", &result);
        NAPI_CALL(env, napi_typeof(env, result, &valuetype));
        if (valuetype != napi_boolean) {
            ANS_LOGE("Wrong argument type. Bool expected.");
            std::string msg = "Incorrect parameter types. The type of isDistributed must be bool.";
            Common::NapiThrow(env, ERROR_PARAM_INVALID, msg);
            return nullptr;
        }
        napi_get_value_bool(env, result, &isDistributed);
        request.SetDistributed(isDistributed);
    }

    return NapiGetNull(env);
}
}
}
