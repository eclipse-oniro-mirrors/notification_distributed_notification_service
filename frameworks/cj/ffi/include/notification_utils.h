/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_NOTIFICATION_UTILS_H
#define OHOS_NOTIFICATION_UTILS_H

#include "cj_ffi/cj_common_ffi.h"
#include "cj_lambda.h"
#include "notification_constant.h"
#include "notification_capsule.h"
#include "notification_slot.h"
#include "notification_request.h"
#include "notification_constant.h"
#include "notification_content.h"
#include "notification_flags.h"
#include "notification_helper.h"
#include "notification_multiline_content.h"
#include "notification_normal_content.h"
#include "notification_picture_content.h"
#include "notification_long_text_content.h"
#include "notification_local_live_view_button.h"
#include "notification_local_live_view_content.h"
#include "notification_progress.h"
#include "notification_time.h"
#include "pixel_map_impl.h"

#include "ans_notification.h"
#include "singleton.h"
#include "securec.h"

extern "C" {
    struct CNotificationBasicContentV2 {
        char* title;
        char* text;
        char* additionalText;
        int64_t lockscreenPicture;
    };

    struct CNotificationLongTextContentV2 {
        char* title;
        char* text;
        char* additionalText;
        int64_t lockscreenPicture;
        char* longText;
        char* briefText;
        char* expandedTitle;
    };

    struct CNotificationMultiLineContentV2 {
        char* title;
        char* text;
        char* additionalText;
        int64_t lockscreenPicture;
        char* briefText;
        char* longTitle;
        CArrString lines;
    };

    struct CNotificationPictureContentV2 {
        char* title;
        char* text;
        char* additionalText;
        int64_t lockscreenPicture;
        char* briefText;
        char* expandedTitle;
        int64_t picture;
    };

    struct CNotificationCapsuleV2 {
        char* title;
        int64_t icon;
        char* backgroundColor;
    };

    struct CNotificationButtonV2 {
        CArrString names;
        CArrI64 icons;
    };

    struct CNotificationTimeV2 {
        int32_t initialTime;
        bool isCountDown;
        bool isPaused;
        bool isInTitle;
    };

    struct CNotificationProgressV2 {
        int32_t maxValue;
        int32_t currentValue;
        bool isPercentage;
    };

    struct CNotificationSystemLiveViewContentV2 {
        char* title;
        char* text;
        char* additionalText;
        int64_t lockscreenPicture;
        int32_t typeCode;
        CNotificationCapsuleV2 capsule;
        CNotificationButtonV2 button;
        CNotificationTimeV2 time;
        CNotificationProgressV2 progress;
    };

    struct CNotificationContentV2 {
        int32_t notificationContentType;
        CNotificationBasicContentV2* normal;
        CNotificationLongTextContentV2* longText;
        CNotificationMultiLineContentV2* multiLine;
        CNotificationPictureContentV2* picture;
        CNotificationSystemLiveViewContentV2* systemLiveView;
    };

    struct CDistributedOptionsV2 {
        bool isDistributed;
        CArrString supportDisplayDevices;
        CArrString supportOperateDevices;
    };

    enum class ContentTypeV2 {
        NOTIFICATION_CONTENT_BASIC_TEXT,
        NOTIFICATION_CONTENT_LONG_TEXT,
        NOTIFICATION_CONTENT_PICTURE,
        NOTIFICATION_CONTENT_CONVERSATION,
        NOTIFICATION_CONTENT_MULTILINE,
        NOTIFICATION_CONTENT_LOCAL_LIVE_VIEW,
        NOTIFICATION_CONTENT_LIVE_VIEW
    };

    enum class SlotTypeV2 {
        UNKNOWN_TYPE = 0,
        SOCIAL_COMMUNICATION = 1,
        SERVICE_INFORMATION = 2,
        CONTENT_INFORMATION = 3,
        LIVE_VIEW = 4,
        CUSTOMER_SERVICE = 5,
        OTHER_TYPES = 0xFFFF,
    };

    enum class SlotLevel {
        LEVEL_NONE = 0,       // the notification function is disabled.
        LEVEL_MIN = 1,        // the notifications function is disabled on the notification panel,
                            // with no banner or prompt tone
        LEVEL_LOW = 2,        // the notifications are displayed on the notification panel,
                            // with no banner or prompt tone
        LEVEL_DEFAULT = 3,    // the notification function is enabled and notifications are displayed,
                            // on the notification panel, with a banner and a prompt tone.
        LEVEL_HIGH = 4,       // the notifications are displayed on the notification panel,
                            // with a banner and a prompt tone
        LEVEL_UNDEFINED = 0xFFFF,  // the notification does not define an level.
    };

    enum class FlagStatus {
        NONE = 0,
        OPEN = 1,
        CLOSE = 2,
    };

    struct CNotificationFlagsV2 {
        int32_t soundEnabled = 0;
        int32_t vibrationEnabled = 0;
    };

    struct CNotificationRequestV2 {
        CNotificationContentV2 notificationContent;
        int32_t id;
        int32_t notificationSlotType;
        bool isOngoing;
        bool isUnremovable;
        int64_t deliveryTime;
        bool tapDismissed;
        int64_t autoDeletedTime;
        uint32_t color;
        bool colorEnabled;
        bool isAlertOnce;
        bool isStopwatch;
        bool isCountDown;
        bool isFloatingIcon;
        char* label;
        int32_t badgeIconStyle;
        bool showDeliveryTime;
        int64_t smallIcon;
        int64_t largeIcon;
        char* creatorBundleName;
        int32_t creatorUid;
        int32_t creatorPid;
        int32_t creatorUserId;
        char* hashCode;
        char* groupName;
        CDistributedOptionsV2* distributedOption;
        CNotificationFlagsV2 notificationFlags;
        uint32_t badgeNumber;
        char* appMessageId;
    };

    struct CArrayNotificationRequestV2 {
        CNotificationRequestV2** head;
        int64_t size;
    };

    struct CNotificationSlotV2 {
        int32_t notificationType;
        int32_t level;
        char* desc;
        bool badgeFlag;
        bool bypassDnd;
        int32_t lockscreenVisibility;
        bool vibrationEnabled;
        char* sound;
        bool lightEnabled;
        int32_t lightColor;
        CArrI64 vibrationValues;
        bool enabled;
    };

    struct CArrayNotificationSlotsV2 {
        CNotificationSlotV2* head;
        int64_t size;
    };

    struct CNotificationBundleOptionV2 {
        char* bundle;
        int32_t uid;
    };
}

namespace OHOS {
namespace CJSystemapi {
namespace Notification {
constexpr int32_t STR_MAX_SIZE = 204;
constexpr int32_t LONG_STR_MAX_SIZE = 1028;
constexpr int32_t ERR_OK = 0;
constexpr uint32_t MAX_ICON_SIZE = 192 * 1024;
constexpr int32_t SHORT_STR_SIZE = 1024;
constexpr int32_t LONG_STR_SIZE = 3072;

char *MallocCString(const std::string &origin);
bool GetNotificationSupportDisplayDevicesV2(
    CDistributedOptionsV2* distributedOption,
    OHOS::Notification::NotificationRequest request);
bool GetNotificationSupportOperateDevicesV2(
    CDistributedOptionsV2* distributedOption,
    OHOS::Notification::NotificationRequest request);
bool GetNotificationRequestDistributedOptionsV2(
    CDistributedOptionsV2* distributedOption,
    OHOS::Notification::NotificationRequest request);
bool GetNotificationRequestByNumberV2(
    CNotificationRequestV2 cjRequest, OHOS::Notification::NotificationRequest &request);
bool GetNotificationRequestByStringV2(
    CNotificationRequestV2 cjRequest, OHOS::Notification::NotificationRequest &request);
bool GetNotificationRequestByBoolV2(
    CNotificationRequestV2 cjRequest, OHOS::Notification::NotificationRequest &request);
bool GetNotificationRequestByCustomV2(
    CNotificationRequestV2 cjRequest, OHOS::Notification::NotificationRequest &request);
bool GetNotificationBasicContentDetailedV2(CNotificationBasicContentV2* contentResult,
    std::shared_ptr<OHOS::Notification::NotificationBasicContent> basicContent);
bool GetNotificationBasicContentV2(CNotificationBasicContentV2* contentResult,
    OHOS::Notification::NotificationRequest &request);
bool GetNotificationLongTextContentDetailedV2(CNotificationLongTextContentV2* contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLongTextContent> &longContent);
bool GetNotificationLongTextContentV2(CNotificationLongTextContentV2* contentResult,
    OHOS::Notification::NotificationRequest &request);
bool GetNotificationPictureContentDetailedV2(CNotificationPictureContentV2* contentResult,
    std::shared_ptr<OHOS::Notification::NotificationPictureContent> &pictureContent);
bool GetNotificationPictureContentV2(CNotificationPictureContentV2* contentResult,
    OHOS::Notification::NotificationRequest &request);
bool GetNotificationMultiLineContentLinesV2(CNotificationMultiLineContentV2* result,
    std::shared_ptr<OHOS::Notification::NotificationMultiLineContent> &multiLineContent);
bool GetNotificationMultiLineContentV2(CNotificationMultiLineContentV2* contentResult,
    OHOS::Notification::NotificationRequest &request);
bool GetNotificationLocalLiveViewCapsuleV2(CNotificationSystemLiveViewContentV2* contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLocalLiveViewContent> &content);
bool GetNotificationLocalLiveViewButtonV2(CNotificationSystemLiveViewContentV2* contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLocalLiveViewContent> &content);
bool GetNotificationLocalLiveViewProgressV2(CNotificationSystemLiveViewContentV2* contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLocalLiveViewContent> &content);
bool GetNotificationLocalLiveViewTimeV2(CNotificationSystemLiveViewContentV2* contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLocalLiveViewContent> &content);
bool GetNotificationLocalLiveViewContentDetailedV2(CNotificationSystemLiveViewContentV2* contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLocalLiveViewContent> &content);
bool GetNotificationLocalLiveViewContentV2(CNotificationSystemLiveViewContentV2* contentResult,
    OHOS::Notification::NotificationRequest &request);
bool SlotTypeCJToCV2(const SlotTypeV2 &inType, OHOS::Notification::NotificationConstant::SlotType &outType);
bool SlotTypeCToCJV2(const OHOS::Notification::NotificationConstant::SlotType &inType, SlotTypeV2 &outType);
bool SlotLevelCToCJV2(const OHOS::Notification::NotificationSlot::NotificationLevel &inLevel, SlotLevel &outLevel);
bool ContentTypeCJToCV2(const ContentTypeV2 &inType, OHOS::Notification::NotificationContent::Type &outType);
bool ContentTypeCToCJV2(const OHOS::Notification::NotificationContent::Type &inType, ContentTypeV2 &outType);
bool GetNotificationSlotTypeV2(int32_t slotType, OHOS::Notification::NotificationRequest &request);
bool GetNotificationContentV2(CNotificationContentV2 &content, OHOS::Notification::NotificationRequest &request);
bool GetNotificationSmallIconV2(int64_t smallIcon, OHOS::Notification::NotificationRequest &request);
bool GetNotificationLargeIconV2(int64_t largeIcon, OHOS::Notification::NotificationRequest &request);
bool SetNotificationSlotV2(const OHOS::Notification::NotificationSlot &slot, CNotificationSlotV2 &notificationSlot);
void SetNotificationRequestByStringV2(const OHOS::Notification::NotificationRequest *request,
    CNotificationRequestV2 &notificationRequest);
bool SetNotificationRequestByNumberV2(const OHOS::Notification::NotificationRequest *request,
    CNotificationRequestV2 &notificationRequest);
void SetNotificationRequestByBoolV2(const OHOS::Notification::NotificationRequest *request,
    CNotificationRequestV2 &notificationRequest);
void SetNotificationRequestByPixelMapV2(const OHOS::Notification::NotificationRequest *request,
    CNotificationRequestV2 &notificationRequest);
bool SetNotificationBasicContentV2(const OHOS::Notification::NotificationBasicContent *basicContent,
    CNotificationBasicContentV2* normal);
bool SetNotificationLongTextContentV2(OHOS::Notification::NotificationBasicContent *basicContent,
    CNotificationLongTextContentV2* longText);
bool SetNotificationPictureContentV2(OHOS::Notification::NotificationBasicContent *basicContent,
    CNotificationPictureContentV2* picture);
bool SetNotificationMultiLineContentV2(OHOS::Notification::NotificationBasicContent *basicContent,
    CNotificationMultiLineContentV2* multiLine);
bool SetCapsuleV2(const OHOS::Notification::NotificationCapsule &capsule, CNotificationCapsuleV2 &cCapsule);
bool SetButtonV2(const OHOS::Notification::NotificationLocalLiveViewButton &button, CNotificationButtonV2 &cButton);
bool SetNotificationLocalLiveViewContentDetailedV2(
    OHOS::Notification::NotificationLocalLiveViewContent *localLiveViewContent,
    CNotificationSystemLiveViewContentV2* systemLiveView);
bool SetNotificationLocalLiveViewContentV2(OHOS::Notification::NotificationBasicContent *basicContent,
    CNotificationSystemLiveViewContentV2* systemLiveView);
bool SetNotificationContentDetailedV2(const ContentTypeV2 &type,
    const std::shared_ptr<OHOS::Notification::NotificationContent> &content,
    CNotificationContentV2 &notificationContent);
bool SetNotificationContentV2(const std::shared_ptr<OHOS::Notification::NotificationContent> &content,
    CNotificationContentV2 &notificationContent);
bool SetNotificationFlagsV2(const std::shared_ptr<OHOS::Notification::NotificationFlags> &flags,
    CNotificationFlagsV2 &notificationFlags);
bool SetNotificationRequestByCustomV2(const OHOS::Notification::NotificationRequest *request,
    CNotificationRequestV2 &notificationRequest);
bool SetNotificationRequestV2(const OHOS::Notification::NotificationRequest *request,
    CNotificationRequestV2 &notificationRequest);
}
} // namespace CJSystemapi
} // namespace OHOS

#endif // OHOS_NOTIFICATION_UTILS_H