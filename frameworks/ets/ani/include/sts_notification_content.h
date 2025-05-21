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

#ifndef BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_CONVERT_NOTIFICATION_H
#define BASE_NOTIFICATION_DISTRIBUTED_NOTIFICATION_SERVICE_FRAMEWORKS_ETS_ANI_INCLUDE_STS_CONVERT_NOTIFICATION_H
#include "ani.h"

#include "notification_progress.h"
#include "notification_time.h"
#include "notification_icon_button.h"
#include "notification_local_live_view_button.h"
#include "notification_capsule.h"

#include "notification_content.h"
#include "notification_basic_content.h"
#include "notification_normal_content.h"
#include "notification_long_text_content.h"
#include "notification_multiline_content.h"
#include "notification_picture_content.h"
#include "notification_live_view_content.h"
#include "notification_local_live_view_content.h"

using LiveViewStatus = OHOS::Notification::NotificationLiveViewContent::LiveViewStatus;
using LiveViewTypes = OHOS::Notification::NotificationLocalLiveViewContent::LiveViewTypes;
namespace OHOS {
namespace NotificationSts {
using namespace OHOS::Notification;

enum STSLiveViewStatus {
    LIVE_VIEW_CREATE = 0,
    LIVE_VIEW_INCREMENTAL_UPDATE = 1,
    LIVE_VIEW_END = 2,
    LIVE_VIEW_FULL_UPDATE = 3
};

class StsLiveViewStatusUtils {
public:
static bool StsToC(const STSLiveViewStatus inType, LiveViewStatus &outType);
static bool CToSts(const LiveViewStatus inType, STSLiveViewStatus &outType);
};

bool LiveViewStatusEtsToC(ani_env *env, ani_enum_item enumItem, LiveViewStatus &liveViewStatus);
bool LiveViewStatusCToEts(ani_env *env, LiveViewStatus liveViewStatus, ani_enum_item &enumItem);

bool LiveViewTypesEtsToC(ani_env *env, ani_enum_item enumItem, LiveViewTypes &liveViewTypes);
bool LiveViewTypesCToEts(ani_env *env, LiveViewTypes liveViewTypes, ani_enum_item &enumItem);

void UnWarpNotificationProgress(ani_env *env, ani_object obj, NotificationProgress &notificationProgress);
bool WarpNotificationProgress(ani_env *env, const NotificationProgress &progress, ani_object &progressObject);

void UnWarpNotificationTime(ani_env *env, ani_object obj, NotificationTime &notificationTime);
bool WarpNotificationTime(ani_env *env, const NotificationTime &time, bool isInitialTimeExist, ani_object &timeObject);

ani_status UnWarpNotificationIconButton(ani_env *env, ani_object obj,
    NotificationIconButton &iconButton);
ani_object WarpNotificationIconButton(ani_env *env, const NotificationIconButton &button);
ani_status GetIconButtonArray(ani_env *env,
    ani_object param, const char *name, std::vector<NotificationIconButton> &res);
ani_object GetAniIconButtonArray(ani_env *env, const std::vector<NotificationIconButton> buttons);

void UnWarpNotificationLocalLiveViewButton(ani_env *env, ani_object obj,
    NotificationLocalLiveViewButton &button);
bool WarpNotificationLocalLiveViewButton(ani_env *env, const NotificationLocalLiveViewButton &button,
    ani_object &buttonObject);

void UnWarpNotificationCapsule(ani_env *env, ani_object obj, NotificationCapsule &capsule);
bool WarpNotificationCapsule(ani_env *env, const NotificationCapsule &capsule, ani_object &capsuleObject);

ani_status UnWarpNotificationBasicContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationBasicContent> basicContent);

ani_status UnWarpNotificationNormalContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationNormalContent> &normalContent);
ani_status UnWarpNotificationLongTextContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationLongTextContent> &longTextContent);
ani_status UnWarpNotificationMultiLineContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationMultiLineContent> &multiLineContent);
ani_status UnWarpNotificationPictureContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationPictureContent> &pictureContent);
ani_status UnWarpNotificationLiveViewContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationLiveViewContent> &liveViewContent);
ani_status UnWarpNotificationLocalLiveViewContent(ani_env *env, ani_object obj,
    std::shared_ptr<NotificationLocalLiveViewContent> &localLiveViewContent);

bool SetNotificationContent(ani_env* env, std::shared_ptr<NotificationContent> ncContent, ani_object &ncObj);
} // namespace NotificationSts
} // OHOS
#endif