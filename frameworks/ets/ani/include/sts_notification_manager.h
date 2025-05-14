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

#ifndef OHOS_DISTRIBUTED_NOTIFICATION_SERVER_STS_NOTIFICATION_MANAGER_H
#define OHOS_DISTRIBUTED_NOTIFICATION_SERVER_STS_NOTIFICATION_MANAGER_H
#include "ani.h"
#include "notification_constant.h"
#include "notification_content.h"
#include "notification_slot.h"
#include "notification_button_option.h"
#include "notification_local_live_view_subscriber.h"
#include "sts_runtime.h"

namespace OHOS {
namespace NotificationSts {
using NotificationLocalLiveViewSubscriber = OHOS::Notification::NotificationLocalLiveViewSubscriber;
using SlotType = OHOS::Notification::NotificationConstant::SlotType;
using SlotLevel = OHOS::Notification::NotificationSlot::NotificationLevel;
using ContentType = OHOS::Notification::NotificationContent::Type;
using ButtonOption = OHOS::Notification::NotificationButtonOption;
using NotificationDoNotDisturbDate = OHOS::Notification::NotificationDoNotDisturbDate;
enum STSSlotType {
    UNKNOWN_TYPE = 0,
    SOCIAL_COMMUNICATION = 1,
    SERVICE_INFORMATION = 2,
    CONTENT_INFORMATION = 3,
    LIVE_VIEW = 4,
    CUSTOMER_SERVICE = 5,
    EMERGENCY_INFORMATION = 10,
    OTHER_TYPES = 0xFFFF,
};

enum STSSlotLevel {
    LEVEL_NONE = 0,
    LEVEL_MIN = 1,
    LEVEL_LOW = 2,
    LEVEL_DEFAULT = 3,
    LEVEL_HIGH = 4,
};

enum STSContentType {
    NOTIFICATION_CONTENT_BASIC_TEXT,
    NOTIFICATION_CONTENT_LONG_TEXT,
    NOTIFICATION_CONTENT_PICTURE,
    NOTIFICATION_CONTENT_CONVERSATION,
    NOTIFICATION_CONTENT_MULTILINE,
    NOTIFICATION_CONTENT_SYSTEM_LIVE_VIEW,
    NOTIFICATION_CONTENT_LIVE_VIEW,
};

class StsSlotTypeUtils {
public:
static bool StsToC(const STSSlotType inType, SlotType &outType);
static bool CToSts(const SlotType inType, STSSlotType &outType);
};

class StsSlotLevelUtils {
public:
static bool StsToC(const STSSlotLevel inType, SlotLevel &outType);
static bool CToSts(const SlotLevel inLevel, STSSlotLevel &outLevel);
};

class StsContentTypeUtils {
public:
static bool StsToC(const STSContentType inType, ContentType &outType);
static bool CToSts(const ContentType inType, STSContentType &outType);
};

class StsNotificationLocalLiveViewSubscriber : public NotificationLocalLiveViewSubscriber {
public:
    StsNotificationLocalLiveViewSubscriber();
    virtual ~StsNotificationLocalLiveViewSubscriber();

    /**
     * @brief Called back when a notification is canceled.
     *
     */
    virtual void OnConnected() override;

    /**
     * @brief Called back when the subscriber is disconnected from the ANS.
     *
     */
    virtual void OnDisconnected() override;

    virtual void OnResponse(int32_t notificationId, sptr<ButtonOption> buttonOption) override;

    /**
     * @brief Called back when connection to the ANS has died.
     *
     */
    virtual void OnDied() override;

    /**
     * @brief Sets the callback information by type.
     *
     * @param env Indicates the environment that the API is invoked under.
     * @param type Indicates the type of callback.
     * @param ref Indicates the napi_ref of callback.
     */
    void SetStsNotificationLocalLiveViewSubscriber(ani_env *env, ani_object &localLiveViewSubscriberObj);

    std::unique_ptr<AbilityRuntime::STSNativeReference> &GetStsNotificationLocalLiveViewSubscriber()
    {
        return stsSubscriber_;
    }
private:
    ani_env* GetAniEnv();
private:
    ani_vm* vm_ = nullptr;
    std::unique_ptr<AbilityRuntime::STSNativeReference> stsSubscriber_ = nullptr;
};

bool SlotTypeEtsToC(ani_env *env, ani_enum_item enumItem, SlotType &slotType);
bool SlotTypeCToEts(ani_env *env, SlotType slotType, ani_enum_item &enumItem);

bool SlotLevelEtsToC(ani_env *env, ani_enum_item enumItem, SlotLevel &slotLevel);
bool SlotLevelCToEts(ani_env *env, SlotLevel slotLevel, ani_enum_item &enumItem);

bool ContentTypeEtsToC(ani_env *env, ani_enum_item enumItem, ContentType &contentType);
bool ContentTypeCToEts(ani_env *env, ContentType contentType, ani_enum_item &enumItem);


ani_status UnWarpNotificationButtonOption(ani_env *env, const ani_object buttonOptionObj,
    ButtonOption &buttonOption);
ani_object WarpNotificationButtonOption(ani_env *env, sptr<ButtonOption> buttonOption);
bool WarpNotificationDoNotDisturbDate(
    ani_env *env, const std::shared_ptr<NotificationDoNotDisturbDate> &date, ani_object &outObj);
} // namespace NotificationSts
} // OHOS
#endif