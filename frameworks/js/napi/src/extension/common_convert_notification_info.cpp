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

#include "common_convert_notification_info.h"
#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "js_native_api.h"
#include "js_native_api_types.h"
#include "napi_common.h"
#include "napi_common_util.h"
#include "notification_info.h"
#include "notification_extension_content.h"
#include "notification_constant.h"

namespace OHOS {
namespace NotificationNapi {

napi_value NapiGetNull(napi_env env)
{
    napi_value result = nullptr;
    napi_get_null(env, &result);

    return result;
}

napi_value SetNotificationExtensionContent(const napi_env &env,
    const std::shared_ptr<NotificationExtensionContent> &notificationExtensionContent, napi_value &result)
{
    ANS_LOGD("called");

    if (notificationExtensionContent == nullptr) {
        ANS_LOGE("null notificationExtensionContent");
        return Common::NapiGetBoolean(env, false);
    }
    napi_value value = nullptr;
    // title: string;
    napi_create_string_utf8(env, notificationExtensionContent->GetTitle().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "title", value);

    // text: string;
    napi_create_string_utf8(env, notificationExtensionContent->GetText().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "notificationText", value);

    return Common::NapiGetBoolean(env, true);
}

napi_value SetNotificationInfo(
    const napi_env &env, const std::shared_ptr<NotificationInfo> &notificationInfo, napi_value &result)
{
    ANS_LOGD("called");

    if (notificationInfo == nullptr) {
        ANS_LOGE("null notificationInfo");
        return Common::NapiGetBoolean(env, false);
    }
    napi_value value = nullptr;

    // readonly hashCode: string;
    napi_create_string_utf8(env, notificationInfo->GetHashCode().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "hashCode", value);

    // readonly notificationSlotType: notificationManager.SlotType;
    napi_create_int32(env, static_cast<int32_t>(notificationInfo->GetNotificationSlotType()), &value);
    napi_set_named_property(env, result, "notificationSlotType", value);

    //readonly content: NotificationExtensionContent;
    std::shared_ptr<NotificationExtensionContent> content = notificationInfo->GetNotificationExtensionContent();
    if (content) {
        napi_value contentResult = nullptr;
        napi_create_object(env, &contentResult);
        if (!SetNotificationExtensionContent(env, content, contentResult)) {
            ANS_LOGE("SetNotificationExtensionContent call failed");
            return Common::NapiGetBoolean(env, false);
        }
        napi_set_named_property(env, result, "content", contentResult);
    } else {
        ANS_LOGE("null content");
        return Common::NapiGetBoolean(env, false);
    }

    // readonly bundleName?: string;
    napi_create_string_utf8(env, notificationInfo->GetBundleName().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "bundleName", value);

    // readonly appName?: string;
    napi_create_string_utf8(env, notificationInfo->GetAppName().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "appName", value);

    // readonly deliveryTime?: number;
    napi_create_int64(env, notificationInfo->GetDeliveryTime(), &value);
    napi_set_named_property(env, result, "deliveryTime", value);

    // readonly groupName?:string;
    napi_create_string_utf8(env, notificationInfo->GetGroupName().c_str(), NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, "groupName", value);

    return Common::NapiGetBoolean(env, true);
}
}
}