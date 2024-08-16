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
    struct CNotificationBasicContent {
        char* title;
        char* text;
        char* additionalText;
        int64_t lockscreenPicture;
    };

    struct CNotificationLongTextContent {
        char* title;
        char* text;
        char* additionalText;
        int64_t lockscreenPicture;
        char* longText;
        char* briefText;
        char* expandedTitle;
    };

    struct CNotificationMultiLineContent {
        char* title;
        char* text;
        char* additionalText;
        int64_t lockscreenPicture;
        char* briefText;
        char* longTitle;
        CArrString lines;
    };

    struct CNotificationPictureContent {
        char* title;
        char* text;
        char* additionalText;
        int64_t lockscreenPicture;
        char* briefText;
        char* expandedTitle;
        int64_t picture;
    };

    struct CNotificationCapsule {
        char* title;
        int64_t icon;
        char* backgroundColor;
    };

    struct CNotificationButton {
        CArrString names;
        CArrI64 icons;
    };

    struct CNotificationTime {
        int32_t initialTime;
        bool isCountDown;
        bool isPaused;
        bool isInTitle;
    };

    struct CNotificationProgress {
        int32_t maxValue;
        int32_t currentValue;
        bool isPercentage;
    };

    struct CNotificationSystemLiveViewContent {
        char* title;
        char* text;
        char* additionalText;
        int64_t lockscreenPicture;
        int32_t typeCode;
        CNotificationCapsule capsule;
        CNotificationButton button;
        CNotificationTime time;
        CNotificationProgress progress;
    };

    struct CNotificationContent {
        int32_t notificationContentType;
        CNotificationBasicContent* normal;
        CNotificationLongTextContent* longText;
        CNotificationMultiLineContent* multiLine;
        CNotificationPictureContent* picture;
        CNotificationSystemLiveViewContent* systemLiveView;
    };

    struct CDistributedOptions {
        bool isDistributed;
        CArrString supportDisplayDevices;
        CArrString supportOperateDevices;
    };

    enum class ContentType {
        NOTIFICATION_CONTENT_BASIC_TEXT,
        NOTIFICATION_CONTENT_LONG_TEXT,
        NOTIFICATION_CONTENT_PICTURE,
        NOTIFICATION_CONTENT_CONVERSATION,
        NOTIFICATION_CONTENT_MULTILINE,
        NOTIFICATION_CONTENT_LOCAL_LIVE_VIEW,
        NOTIFICATION_CONTENT_LIVE_VIEW
    };

    enum class SlotType {
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

    struct CNotificationFlags {
        int32_t soundEnabled = 0;
        int32_t vibrationEnabled = 0;
    };

    struct CNotificationRequest {
        CNotificationContent notificationContent;
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
        CDistributedOptions* distributedOption;
        CNotificationFlags notificationFlags;
        uint32_t badgeNumber;
        char* appMessageId;
    };

    struct CArrayNotificationRequest {
        CNotificationRequest** head;
        int64_t size;
    };

    struct CNotificationSlot {
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

    struct CArrayNotificationSlots {
        CNotificationSlot* head;
        int64_t size;
    };

    struct CNotificationBundleOption {
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

char *MallocCString(const std::string &origin);
bool GetNotificationSupportDisplayDevices(
    CDistributedOptions* distributedOption,
    OHOS::Notification::NotificationRequest request);
bool GetNotificationSupportOperateDevices(
    CDistributedOptions* distributedOption,
    OHOS::Notification::NotificationRequest request);
bool GetNotificationRequestDistributedOptions(
    CDistributedOptions* distributedOption,
    OHOS::Notification::NotificationRequest request);
bool GetNotificationRequestByNumber(CNotificationRequest cjRequest, OHOS::Notification::NotificationRequest &request);
bool GetNotificationRequestByString(CNotificationRequest cjRequest, OHOS::Notification::NotificationRequest &request);
bool GetNotificationRequestByBool(CNotificationRequest cjRequest, OHOS::Notification::NotificationRequest &request);
bool GetNotificationRequestByCustom(CNotificationRequest cjRequest, OHOS::Notification::NotificationRequest &request);
bool GetNotificationBasicContentDetailed(CNotificationBasicContent* contentResult,
    std::shared_ptr<OHOS::Notification::NotificationBasicContent> basicContent);
bool GetNotificationBasicContent(CNotificationBasicContent* contentResult,
    OHOS::Notification::NotificationRequest &request);
bool GetNotificationLongTextContentDetailed(CNotificationLongTextContent* contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLongTextContent> &longContent);
bool GetNotificationLongTextContent(CNotificationLongTextContent* contentResult,
    OHOS::Notification::NotificationRequest &request);
bool GetNotificationPictureContentDetailed(CNotificationPictureContent* contentResult,
    std::shared_ptr<OHOS::Notification::NotificationPictureContent> &pictureContent);
bool GetNotificationPictureContent(CNotificationPictureContent* contentResult,
    OHOS::Notification::NotificationRequest &request);
bool GetNotificationMultiLineContentLines(CNotificationMultiLineContent* result,
    std::shared_ptr<OHOS::Notification::NotificationMultiLineContent> &multiLineContent);
bool GetNotificationMultiLineContent(CNotificationMultiLineContent* contentResult,
    OHOS::Notification::NotificationRequest &request);
bool GetNotificationLocalLiveViewCapsule(CNotificationSystemLiveViewContent* contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLocalLiveViewContent> &content);
bool GetNotificationLocalLiveViewButton(CNotificationSystemLiveViewContent* contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLocalLiveViewContent> &content);
bool GetNotificationLocalLiveViewProgress(CNotificationSystemLiveViewContent* contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLocalLiveViewContent> &content);
bool GetNotificationLocalLiveViewTime(CNotificationSystemLiveViewContent* contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLocalLiveViewContent> &content);
bool GetNotificationLocalLiveViewContentDetailed(CNotificationSystemLiveViewContent* contentResult,
    std::shared_ptr<OHOS::Notification::NotificationLocalLiveViewContent> &content);
bool GetNotificationLocalLiveViewContent(CNotificationSystemLiveViewContent* contentResult,
    OHOS::Notification::NotificationRequest &request);
bool SlotTypeCJToC(const SlotType &inType, OHOS::Notification::NotificationConstant::SlotType &outType);
bool SlotTypeCToCJ(const OHOS::Notification::NotificationConstant::SlotType &inType, SlotType &outType);
bool SlotLevelCToCJ(const OHOS::Notification::NotificationSlot::NotificationLevel &inLevel, SlotLevel &outLevel);
bool ContentTypeCJToC(const ContentType &inType, OHOS::Notification::NotificationContent::Type &outType);
bool ContentTypeCToCJ(const OHOS::Notification::NotificationContent::Type &inType, ContentType &outType);
bool GetNotificationSlotType(int32_t slotType, OHOS::Notification::NotificationRequest &request);
bool GetNotificationContent(CNotificationContent &content, OHOS::Notification::NotificationRequest &request);
bool GetNotificationSmallIcon(int64_t smallIcon, OHOS::Notification::NotificationRequest &request);
bool GetNotificationLargeIcon(int64_t largeIcon, OHOS::Notification::NotificationRequest &request);
bool SetNotificationSlot(const OHOS::Notification::NotificationSlot &slot, CNotificationSlot &notificationSlot);
void SetNotificationRequestByString(const OHOS::Notification::NotificationRequest *request,
    CNotificationRequest &notificationRequest);
bool SetNotificationRequestByNumber(const OHOS::Notification::NotificationRequest *request,
    CNotificationRequest &notificationRequest);
void SetNotificationRequestByBool(const OHOS::Notification::NotificationRequest *request,
    CNotificationRequest &notificationRequest);
void SetNotificationRequestByPixelMap(const OHOS::Notification::NotificationRequest *request,
    CNotificationRequest &notificationRequest);
bool SetNotificationBasicContent(const OHOS::Notification::NotificationBasicContent *basicContent,
    CNotificationBasicContent* normal);
bool SetNotificationLongTextContent(OHOS::Notification::NotificationBasicContent *basicContent,
    CNotificationLongTextContent* longText);
bool SetNotificationPictureContent(OHOS::Notification::NotificationBasicContent *basicContent,
    CNotificationPictureContent* picture);
bool SetNotificationMultiLineContent(OHOS::Notification::NotificationBasicContent *basicContent,
    CNotificationMultiLineContent* multiLine);
bool SetCapsule(const OHOS::Notification::NotificationCapsule &capsule, CNotificationCapsule &cCapsule);
bool SetButton(const OHOS::Notification::NotificationLocalLiveViewButton &button, CNotificationButton &cButton);
bool SetNotificationLocalLiveViewContentDetailed(
    OHOS::Notification::NotificationLocalLiveViewContent *localLiveViewContent,
    CNotificationSystemLiveViewContent* systemLiveView);
bool SetNotificationLocalLiveViewContent(OHOS::Notification::NotificationBasicContent *basicContent,
    CNotificationSystemLiveViewContent* systemLiveView);
bool SetNotificationContentDetailed(const ContentType &type,
    const std::shared_ptr<OHOS::Notification::NotificationContent> &content,
    CNotificationContent &notificationContent);
bool SetNotificationContent(const std::shared_ptr<OHOS::Notification::NotificationContent> &content,
    CNotificationContent &notificationContent);
bool SetNotificationFlags(const std::shared_ptr<OHOS::Notification::NotificationFlags> &flags,
    CNotificationFlags &notificationFlags);
bool SetNotificationRequestByCustom(const OHOS::Notification::NotificationRequest *request,
    CNotificationRequest &notificationRequest);
bool SetNotificationRequest(const OHOS::Notification::NotificationRequest *request,
    CNotificationRequest &notificationRequest);
}
} // namespace CJSystemapi
} // namespace OHOS

#endif // OHOS_NOTIFICATION_UTILS_H