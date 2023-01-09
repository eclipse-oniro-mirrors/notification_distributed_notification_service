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

#include <gtest/gtest.h>

#include "notification_bundle_option.h"
#include "notification_do_not_disturb_date.h"
#include "enabled_notification_callback_data.h"
#include "notification_request.h"
#include "notification_slot.h"
#include "notification_sorting_map.h"
#include "notification_subscriber.h"
#include "ans_inner_errors.h"
#include "errors.h"
#include "notification_helper.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationHelperTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: AddNotificationSlot_00001
 * @tc.desc: Test AddNotificationSlot parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, AddNotificationSlot_00001, Function | SmallTest | Level1)
{
    NotificationSlot slot;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.AddNotificationSlot(slot);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: AddSlotByType_00001
 * @tc.desc: Test AddSlotByType parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, AddSlotByType_00001, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SERVICE_REMINDER;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.AddSlotByType(slotType);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: AddNotificationSlots_00001
 * @tc.desc: Test AddNotificationSlots parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, AddNotificationSlots_00001, Function | SmallTest | Level1)
{
    std::vector<NotificationSlot> slots;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.AddNotificationSlots(slots);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: RemoveNotificationSlot_00001
 * @tc.desc: Test RemoveNotificationSlot parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, RemoveNotificationSlot_00001, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SERVICE_REMINDER;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.RemoveNotificationSlot(slotType);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: RemoveAllSlots_00001
 * @tc.desc: Test RemoveAllSlots parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, RemoveAllSlots_00001, Function | SmallTest | Level1)
{
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.RemoveAllSlots();
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: GetNotificationSlot_00001
 * @tc.desc: Test GetNotificationSlot parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetNotificationSlot_00001, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SERVICE_REMINDER;
    sptr<NotificationSlot> slot = nullptr;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetNotificationSlot(slotType, slot);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: GetNotificationSlots_00001
 * @tc.desc: Test GetNotificationSlots parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetNotificationSlots_00001, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationSlot>> slots;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetNotificationSlots(slots);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: GetNotificationSlotNumAsBundle_00001
 * @tc.desc: Test GetNotificationSlotNumAsBundle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetNotificationSlotNumAsBundle_00001, Function | SmallTest | Level1)
{
    NotificationBundleOption bundleOption;
    uint64_t num = 10;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetNotificationSlotNumAsBundle(bundleOption, num);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: PublishNotification_00001
 * @tc.desc: Test PublishNotification parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, PublishNotification_00001, Function | SmallTest | Level1)
{
    NotificationRequest request;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.PublishNotification(request);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: PublishNotification_00002
 * @tc.desc: Test PublishNotification parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, PublishNotification_00002, Function | SmallTest | Level1)
{
    NotificationRequest request;
    std::string deviceId = "DeviceId";
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.PublishNotification(request, deviceId);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: PublishNotification_00003
 * @tc.desc: Test PublishNotification parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, PublishNotification_00003, Function | SmallTest | Level1)
{
    std::string label = "Label";
    NotificationRequest request;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.PublishNotification(label, request);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: CancelNotification_00001
 * @tc.desc: Test CancelNotification parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, CancelNotification_00001, Function | SmallTest | Level1)
{
    int32_t notificationId = 10;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.CancelNotification(notificationId);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: CancelNotification_00002
 * @tc.desc: Test CancelNotification parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, CancelNotification_00002, Function | SmallTest | Level1)
{
    std::string label = "Label";
    int32_t notificationId = 10;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.CancelNotification(label, notificationId);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: CancelAllNotifications_00001
 * @tc.desc: Test CancelAllNotifications parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, CancelAllNotifications_00001, Function | SmallTest | Level1)
{
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.CancelAllNotifications();
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: CancelAsBundle_00001
 * @tc.desc: Test CancelAsBundle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, CancelAsBundle_00001, Function | SmallTest | Level1)
{
    int32_t notificationId = 10;
    std::string representativeBundle = "RepresentativeBundle";
    int32_t userId = 10;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.CancelAsBundle(notificationId, representativeBundle, userId);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_UID);
}

/**
 * @tc.name: GetActiveNotificationNums_00001
 * @tc.desc: Test GetActiveNotificationNums parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetActiveNotificationNums_00001, Function | SmallTest | Level1)
{
    uint64_t num = 10;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetActiveNotificationNums(num);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: GetActiveNotifications_00001
 * @tc.desc: Test GetActiveNotifications parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetActiveNotifications_00001, Function | SmallTest | Level1)
{
    std::vector<sptr<NotificationRequest>> request;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetActiveNotifications(request);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: GetCurrentAppSorting_00001
 * @tc.desc: Test GetCurrentAppSorting parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetCurrentAppSorting_00001, Function | SmallTest | Level1)
{
    sptr<NotificationSortingMap> sortingMap = nullptr;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetCurrentAppSorting(sortingMap);
    EXPECT_EQ(ret, (int)ERR_ANS_PARCELABLE_FAILED);
}

/**
 * @tc.name: SetNotificationAgent_00001
 * @tc.desc: Test SetNotificationAgent parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, SetNotificationAgent_00001, Function | SmallTest | Level1)
{
    std::string agent = "Agent";
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetNotificationAgent(agent);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: GetNotificationAgent_00001
 * @tc.desc: Test GetNotificationAgent parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetNotificationAgent_00001, Function | SmallTest | Level1)
{
    std::string agent = "Agent";
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetNotificationAgent(agent);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: CanPublishNotificationAsBundle_00001
 * @tc.desc: Test CanPublishNotificationAsBundle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, CanPublishNotificationAsBundle_00001, Function | SmallTest | Level1)
{
    std::string representativeBundle = "RepresentativeBundle";
    bool canPublish = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.CanPublishNotificationAsBundle(representativeBundle, canPublish);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: PublishNotificationAsBundle_00001
 * @tc.desc: Test PublishNotificationAsBundle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, PublishNotificationAsBundle_00001, Function | SmallTest | Level1)
{
    std::string representativeBundle = "RepresentativeBundle";
    NotificationRequest request;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.PublishNotificationAsBundle(representativeBundle, request);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetNotificationBadgeNum_00001
 * @tc.desc: Test SetNotificationBadgeNum parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, SetNotificationBadgeNum_00001, Function | SmallTest | Level1)
{
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetNotificationBadgeNum();
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: SetNotificationBadgeNum_00002
 * @tc.desc: Test SetNotificationBadgeNum parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, SetNotificationBadgeNum_00002, Function | SmallTest | Level1)
{
    int32_t num = 10;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetNotificationBadgeNum(num);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: IsAllowedNotify_00001
 * @tc.desc: Test IsAllowedNotify parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, IsAllowedNotify_00001, Function | SmallTest | Level1)
{
    bool allowed = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.IsAllowedNotify(allowed);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: IsAllowedNotifySelf_00001
 * @tc.desc: Test IsAllowedNotifySelf parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, IsAllowedNotifySelf_00001, Function | SmallTest | Level1)
{
    bool allowed = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.IsAllowedNotifySelf(allowed);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: RequestEnableNotification_00001
 * @tc.desc: Test RequestEnableNotification parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, RequestEnableNotification_00001, Function | SmallTest | Level1)
{
    std::string deviceId = "DeviceId";
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.RequestEnableNotification(deviceId);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: AreNotificationsSuspended_00001
 * @tc.desc: Test AreNotificationsSuspended parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, AreNotificationsSuspended_00001, Function | SmallTest | Level1)
{
    bool suspended = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.AreNotificationsSuspended(suspended);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: HasNotificationPolicyAccessPermission_00001
 * @tc.desc: Test HasNotificationPolicyAccessPermission parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, HasNotificationPolicyAccessPermission_00001, Function | SmallTest | Level1)
{
    bool hasPermission = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.HasNotificationPolicyAccessPermission(hasPermission);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: GetBundleImportance_00001
 * @tc.desc: Test GetBundleImportance parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetBundleImportance_00001, Function | SmallTest | Level1)
{
    NotificationSlot::NotificationLevel importance = NotificationSlot::NotificationLevel::LEVEL_NONE;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetBundleImportance(importance);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: RemoveNotification_00001
 * @tc.desc: Test RemoveNotification parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, RemoveNotification_00001, Function | SmallTest | Level1)
{
    std::string key = "Key";
    int32_t removeReason = 2;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.RemoveNotification(key, removeReason);
    EXPECT_EQ(ret, (int)ERR_ANS_NOTIFICATION_NOT_EXISTS);
}

/**
 * @tc.name: RemoveNotification_00002
 * @tc.desc: Test RemoveNotification parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, RemoveNotification_00002, Function | SmallTest | Level1)
{
    NotificationBundleOption bundleOption;
    int32_t notificationId = 10;
    std::string label = "Label";
    int32_t removeReason = 2;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.RemoveNotification(bundleOption, notificationId, label, removeReason);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: RemoveAllNotifications_00001
 * @tc.desc: Test RemoveAllNotifications parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, RemoveAllNotifications_00001, Function | SmallTest | Level1)
{
    NotificationBundleOption bundleOption;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.RemoveAllNotifications(bundleOption);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: RemoveNotificationsByBundle_00001
 * @tc.desc: Test RemoveNotificationsByBundle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, RemoveNotificationsByBundle_00001, Function | SmallTest | Level1)
{
    NotificationBundleOption bundleOption;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.RemoveNotificationsByBundle(bundleOption);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: RemoveNotifications_00001
 * @tc.desc: Test RemoveNotifications parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, RemoveNotifications_00001, Function | SmallTest | Level1)
{
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.RemoveNotifications();
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: GetNotificationSlotsForBundle_00001
 * @tc.desc: Test GetNotificationSlotsForBundle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetNotificationSlotsForBundle_00001, Function | SmallTest | Level1)
{
    NotificationBundleOption bundleOption;
    std::vector<sptr<NotificationSlot>> slots;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetNotificationSlotsForBundle(bundleOption, slots);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: UpdateNotificationSlots_00001
 * @tc.desc: Test UpdateNotificationSlots parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, UpdateNotificationSlots_00001, Function | SmallTest | Level1)
{
    NotificationBundleOption bundleOption;
    std::vector<sptr<NotificationSlot>> slots;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.UpdateNotificationSlots(bundleOption, slots);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetAllActiveNotifications_00001
 * @tc.desc: Test GetAllActiveNotifications parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetAllActiveNotifications_00001, Function | SmallTest | Level1)
{
    std::vector<sptr<Notification>> notification;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetAllActiveNotifications(notification);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: GetAllActiveNotifications_00002
 * @tc.desc: Test GetAllActiveNotifications parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetAllActiveNotifications_00002, Function | SmallTest | Level1)
{
    std::vector<std::string> key;
    std::vector<sptr<Notification>> notification;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetAllActiveNotifications(key, notification);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: IsAllowedNotify_00002
 * @tc.desc: Test IsAllowedNotify parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, IsAllowedNotify_00002, Function | SmallTest | Level1)
{
    NotificationBundleOption bundleOption;
    bool allowed = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.IsAllowedNotify(bundleOption, allowed);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetNotificationsEnabledForAllBundles_00001
 * @tc.desc: Test SetNotificationsEnabledForAllBundles parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, SetNotificationsEnabledForAllBundles_00001, Function | SmallTest | Level1)
{
    std::string deviceId = "DeviceId";
    bool enabled = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetNotificationsEnabledForAllBundles(deviceId, enabled);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: SetNotificationsEnabledForDefaultBundle_00001
 * @tc.desc: Test SetNotificationsEnabledForDefaultBundle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, SetNotificationsEnabledForDefaultBundle_00001, Function | SmallTest | Level1)
{
    std::string deviceId = "DeviceId";
    bool enabled = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetNotificationsEnabledForDefaultBundle(deviceId, enabled);
    EXPECT_EQ(ret, (int)ERR_INVALID_OPERATION);
}

/**
 * @tc.name: SetShowBadgeEnabledForBundle_00001
 * @tc.desc: Test SetShowBadgeEnabledForBundle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, SetShowBadgeEnabledForBundle_00001, Function | SmallTest | Level1)
{
    NotificationBundleOption bundleOption;
    bool enabled = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetShowBadgeEnabledForBundle(bundleOption, enabled);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetShowBadgeEnabledForBundle_00001
 * @tc.desc: Test GetShowBadgeEnabledForBundle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetShowBadgeEnabledForBundle_00001, Function | SmallTest | Level1)
{
    NotificationBundleOption bundleOption;
    bool enabled = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetShowBadgeEnabledForBundle(bundleOption, enabled);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetShowBadgeEnabled_00001
 * @tc.desc: Test GetShowBadgeEnabled parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetShowBadgeEnabled_00001, Function | SmallTest | Level1)
{
    bool enabled = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetShowBadgeEnabled(enabled);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: CancelGroup_00001
 * @tc.desc: Test CancelGroup parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, CancelGroup_00001, Function | SmallTest | Level1)
{
    std::string groupName = "GroupName";
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.CancelGroup(groupName);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: RemoveGroupByBundle_00001
 * @tc.desc: Test RemoveGroupByBundle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, RemoveGroupByBundle_00001, Function | SmallTest | Level1)
{
    NotificationBundleOption bundleOption;
    std::string groupName = "GroupName";
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.RemoveGroupByBundle(bundleOption, groupName);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetDoNotDisturbDate_00001
 * @tc.desc: Test SetDoNotDisturbDate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, SetDoNotDisturbDate_00001, Function | SmallTest | Level1)
{
    NotificationDoNotDisturbDate doNotDisturbDate;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetDoNotDisturbDate(doNotDisturbDate);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: GetDoNotDisturbDate_00001
 * @tc.desc: Test GetDoNotDisturbDate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetDoNotDisturbDate_00001, Function | SmallTest | Level1)
{
    NotificationDoNotDisturbDate doNotDisturbDate;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetDoNotDisturbDate(doNotDisturbDate);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: DoesSupportDoNotDisturbMode_00001
 * @tc.desc: Test DoesSupportDoNotDisturbMode parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, DoesSupportDoNotDisturbMode_00001, Function | SmallTest | Level1)
{
    bool doesSupport = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.DoesSupportDoNotDisturbMode(doesSupport);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: IsDistributedEnabled_00001
 * @tc.desc: Test IsDistributedEnabled parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, IsDistributedEnabled_00001, Function | SmallTest | Level1)
{
    bool enabled = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.IsDistributedEnabled(enabled);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: EnableDistributed_00001
 * @tc.desc: Test EnableDistributed parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, EnableDistributed_00001, Function | SmallTest | Level1)
{
    bool enabled = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.EnableDistributed(enabled);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: EnableDistributedByBundle_00001
 * @tc.desc: Test EnableDistributedByBundle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, EnableDistributedByBundle_00001, Function | SmallTest | Level1)
{
    NotificationBundleOption bundleOption;
    bool enabled = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.EnableDistributedByBundle(bundleOption, enabled);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: EnableDistributedSelf_00001
 * @tc.desc: Test EnableDistributedSelf parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, EnableDistributedSelf_00001, Function | SmallTest | Level1)
{
    bool enabled = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.EnableDistributedSelf(enabled);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: IsDistributedEnableByBundle_00001
 * @tc.desc: Test IsDistributedEnableByBundle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, IsDistributedEnableByBundle_00001, Function | SmallTest | Level1)
{
    NotificationBundleOption bundleOption;
    bool enabled = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.IsDistributedEnableByBundle(bundleOption, enabled);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: GetDeviceRemindType_00001
 * @tc.desc: Test GetDeviceRemindType parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetDeviceRemindType_00001, Function | SmallTest | Level1)
{
    NotificationConstant::RemindType remindType = NotificationConstant::RemindType::DEVICE_ACTIVE_REMIND;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetDeviceRemindType(remindType);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: PublishContinuousTaskNotification_00001
 * @tc.desc: Test PublishContinuousTaskNotification parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, PublishContinuousTaskNotification_00001, Function | SmallTest | Level1)
{
    NotificationRequest request;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.PublishContinuousTaskNotification(request);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: CancelContinuousTaskNotification_00001
 * @tc.desc: Test CancelContinuousTaskNotification parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, CancelContinuousTaskNotification_00001, Function | SmallTest | Level1)
{
    std::string label = "label";
    int32_t notificationId = 10;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.CancelContinuousTaskNotification(label, notificationId);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: IsSupportTemplate_00001
 * @tc.desc: Test IsSupportTemplate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, IsSupportTemplate_00001, Function | SmallTest | Level1)
{
    std::string templateName = "TemplateName";
    bool support = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.IsSupportTemplate(templateName, support);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: SetNotificationsEnabledForAllBundles_00002
 * @tc.desc: Test SetNotificationsEnabledForAllBundles parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, SetNotificationsEnabledForAllBundles_00002, Function | SmallTest | Level1)
{
    int32_t userId = 10;
    bool enabled = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetNotificationsEnabledForAllBundles(userId, enabled);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: IsSupportTemplate_00002
 * @tc.desc: Test IsSupportTemplate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, IsSupportTemplate_00002, Function | SmallTest | Level1)
{
    std::string templateName = "TemplateName";
    bool support = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.IsSupportTemplate(templateName, support);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: IsAllowedNotify_00004
 * @tc.desc: Test IsAllowedNotify parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, IsAllowedNotify_00004, Function | SmallTest | Level1)
{
    int32_t userId = 10;
    bool allowed = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.IsAllowedNotify(userId, allowed);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: SetNotificationsEnabledForAllBundles_00003
 * @tc.desc: Test SetNotificationsEnabledForAllBundles parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, SetNotificationsEnabledForAllBundles_00003, Function | SmallTest | Level1)
{
    int32_t userId = 10;
    bool enabled = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetNotificationsEnabledForAllBundles(userId, enabled);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: RemoveNotifications_00002
 * @tc.desc: Test RemoveNotifications parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, RemoveNotifications_00002, Function | SmallTest | Level1)
{
    int32_t userId = 10;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.RemoveNotifications(userId);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: SetDoNotDisturbDate_00002
 * @tc.desc: Test SetDoNotDisturbDate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, SetDoNotDisturbDate_00002, Function | SmallTest | Level1)
{
    int32_t userId = 10;
    NotificationDoNotDisturbDate doNotDisturbDate;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetDoNotDisturbDate(userId, doNotDisturbDate);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: GetDoNotDisturbDate_00002
 * @tc.desc: Test GetDoNotDisturbDate parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetDoNotDisturbDate_00002, Function | SmallTest | Level1)
{
    int32_t userId = 10;
    NotificationDoNotDisturbDate doNotDisturbDate;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetDoNotDisturbDate(userId, doNotDisturbDate);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: SetEnabledForBundleSlot_00001
 * @tc.desc: Test SetEnabledForBundleSlot parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, SetEnabledForBundleSlot_00001, Function | SmallTest | Level1)
{
    NotificationBundleOption bundleOption;
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SERVICE_REMINDER;
    bool enabled = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetEnabledForBundleSlot(bundleOption, slotType, enabled);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetEnabledForBundleSlot_00001
 * @tc.desc: Test GetEnabledForBundleSlot parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetEnabledForBundleSlot_00001, Function | SmallTest | Level1)
{
    NotificationBundleOption bundleOption;
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SERVICE_REMINDER;
    bool enabled = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetEnabledForBundleSlot(bundleOption, slotType, enabled);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetSyncNotificationEnabledWithoutApp_00001
 * @tc.desc: Test SetSyncNotificationEnabledWithoutApp parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, SetSyncNotificationEnabledWithoutApp_00001, Function | SmallTest | Level1)
{
    int32_t userId = 10;
    bool enabled = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetSyncNotificationEnabledWithoutApp(userId, enabled);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: GetSyncNotificationEnabledWithoutApp_00001
 * @tc.desc: Test GetSyncNotificationEnabledWithoutApp parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetSyncNotificationEnabledWithoutApp_00001, Function | SmallTest | Level1)
{
    int32_t userId = 10;
    bool enabled = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetSyncNotificationEnabledWithoutApp(userId, enabled);
    EXPECT_EQ(ret, (int)ERR_OK);
}
}
}