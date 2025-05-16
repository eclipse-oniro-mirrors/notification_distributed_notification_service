/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_SLOT_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_SLOT_H

#include "common.h"

namespace OHOS {
namespace NotificationNapi {
using namespace OHOS::Notification;

struct ParametersInfoAddSlot {
    NotificationSlot slot;
    NotificationConstant::SlotType inType = NotificationConstant::SlotType::OTHER;
    bool isAddSlotByType = false;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoAddSlot {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    NotificationSlot slot;
    NotificationConstant::SlotType inType = NotificationConstant::SlotType::OTHER;
    bool isAddSlotByType = false;
    CallbackPromiseInfo info;
};

struct ParametersInfoAddSlots {
    std::vector<NotificationSlot> slots;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoAddSlots {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    std::vector<NotificationSlot> slots;
    CallbackPromiseInfo info;
};

struct ParametersInfoSetSlotByBundle {
    NotificationBundleOption option;
    std::vector<sptr<NotificationSlot>> slots;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoSetSlotByBundle {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    ParametersInfoSetSlotByBundle params;
    CallbackPromiseInfo info;
};

struct ParametersInfoGetSlot {
    NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoGetSlot {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
    CallbackPromiseInfo info;
    sptr<NotificationSlot> slot = nullptr;
};

struct ParametersInfoGetSlotNumByBundle {
    NotificationBundleOption option;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoGetSlotNumByBundle {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    ParametersInfoGetSlotNumByBundle params;
    CallbackPromiseInfo info;
    uint64_t num = 0;
};

struct AsyncCallbackInfoGetSlots {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    std::vector<sptr<NotificationSlot>> slots;
};

struct ParametersInfoGetSlotsByBundle {
    NotificationBundleOption option;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoGetSlotsByBundle {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    ParametersInfoGetSlotsByBundle params;
    CallbackPromiseInfo info;
    std::vector<sptr<NotificationSlot>> slots;
};

struct ParametersInfoGetSlotByBundle {
    NotificationBundleOption option;
    NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoGetSlotByBundle {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    ParametersInfoGetSlotByBundle params;
    CallbackPromiseInfo info;
    sptr<NotificationSlot> slot;
};

struct ParametersInfoRemoveSlot {
    NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoRemoveSlot {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
    CallbackPromiseInfo info;
};

struct AsyncCallbackInfoRemoveAllSlots {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
};

struct ParametersInfoEnableSlot {
    NotificationBundleOption option;
    NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
    bool enable = false;
    bool isForceControl = false;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoInfoEnableSlot {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    ParametersInfoEnableSlot params;
    CallbackPromiseInfo info;
};

struct ParametersInfoIsEnableSlot {
    NotificationBundleOption option;
    NotificationConstant::SlotType outType = NotificationConstant::SlotType::OTHER;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoInfoIsEnableSlot {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    ParametersInfoIsEnableSlot params;
    bool isEnable = false;
    CallbackPromiseInfo info;
};

struct ParametersInfoSetSlotFlagsByBundle {
    NotificationBundleOption option;
    uint32_t slotFlags;
    napi_ref callback = nullptr;
};

struct ParametersInfoGetSlotFlagsByBundle {
    NotificationBundleOption option;
    napi_ref callback = nullptr;
};

struct AsyncCallbackInfoSetSlotFlagsByBundle {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    ParametersInfoSetSlotFlagsByBundle params;
    CallbackPromiseInfo info;
};

struct AsyncCallbackInfoGetSlotFlagsByBundle {
    napi_env env = nullptr;
    napi_async_work asyncWork = nullptr;
    ParametersInfoGetSlotFlagsByBundle params;
    CallbackPromiseInfo info;
    uint32_t slotFlags = 0;
};

struct AsyncCallbackInfoGetNotificationSettings {
    napi_env env;
    napi_async_work asyncWork = nullptr;
    CallbackPromiseInfo info;
    uint32_t slotFlags = 0;
};

napi_value NapiAddSlot(napi_env env, napi_callback_info info);
napi_value NapiAddSlots(napi_env env, napi_callback_info info);
napi_value NapiSetSlotByBundle(napi_env env, napi_callback_info info);
napi_value NapiGetSlot(napi_env env, napi_callback_info info);
napi_value NapiGetSlotNumByBundle(napi_env env, napi_callback_info info);
napi_value NapiGetSlots(napi_env env, napi_callback_info info);
napi_value NapiGetSlotsByBundle(napi_env env, napi_callback_info info);
napi_value NapiGetSlotByBundle(napi_env env, napi_callback_info info);
napi_value NapiRemoveSlot(napi_env env, napi_callback_info info);
napi_value NapiRemoveAllSlots(napi_env env, napi_callback_info info);
napi_value NapiEnableNotificationSlot(napi_env env, napi_callback_info info);
napi_value NapiIsEnableNotificationSlot(napi_env env, napi_callback_info info);
napi_value NapiSetSlotFlagsByBundle(napi_env env, napi_callback_info info);
napi_value NapiGetSlotFlagsByBundle(napi_env env, napi_callback_info info);
napi_value NapiGetNotificationSettings(napi_env env, napi_callback_info info);

napi_value ParseParametersByAddSlot(const napi_env &env, const napi_callback_info &info, ParametersInfoAddSlot &paras);
napi_value ParseParametersByAddSlots(
    const napi_env &env, const napi_callback_info &info, ParametersInfoAddSlots &paras);
napi_value ParseParametersSetSlotByBundle(
    const napi_env &env, const napi_callback_info &info, ParametersInfoSetSlotByBundle &params);
napi_value ParseParametersByGetSlot(const napi_env &env, const napi_callback_info &info, ParametersInfoGetSlot &paras);
napi_value ParseParametersGetSlotNumByBundle(
    const napi_env &env, const napi_callback_info &info, ParametersInfoGetSlotNumByBundle &params);
napi_value ParseParametersGetSlotsByBundle(
    const napi_env &env, const napi_callback_info &info, ParametersInfoGetSlotsByBundle &params);
napi_value ParseParametersGetSlotByBundle(
    const napi_env &env, const napi_callback_info &info, ParametersInfoGetSlotByBundle &params);
napi_value ParseParametersByRemoveSlot(
    const napi_env &env, const napi_callback_info &info, ParametersInfoRemoveSlot &paras);
napi_value ParseParametersEnableSlot(
    const napi_env &env, const napi_callback_info &info, ParametersInfoEnableSlot &params);
napi_value ParseParametersIsEnableSlot(
    const napi_env &env, const napi_callback_info &info, ParametersInfoIsEnableSlot &params);
napi_value ParseParametersSetSlotFlagsByBundle(
    const napi_env &env, const napi_callback_info &info, ParametersInfoSetSlotFlagsByBundle &params);
napi_value ParseParametersGetSlotFlagsByBundle(
    const napi_env &env, const napi_callback_info &info, ParametersInfoGetSlotFlagsByBundle &params);
}  // namespace NotificationNapi
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_JS_NAPI_SLOT_H