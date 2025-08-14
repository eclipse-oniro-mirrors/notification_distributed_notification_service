/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <cstdint>
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
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class NotificationHelperTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        const char **perms = new const char *[1];
        perms[0] = "ohos.permission.NOTIFICATION_CONTROLLER";
        NativeTokenInfoParams infoInstance = {
            .dcapsNum = 0,
            .permsNum = 1,
            .aclsNum = 0,
            .dcaps = nullptr,
            .perms = perms,
            .acls = nullptr,
            .aplStr = "system_basic",
        };

        uint64_t tokenId;
        infoInstance.processName = "ans_reminder_unit_test";
        tokenId = GetAccessTokenId(&infoInstance);
        SetSelfTokenID(tokenId);
        delete[] perms;
    }
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    void UpdateStatuts(bool isEnable, int status)
    {
        ANS_LOGI("NotificationHelperTest UpdateStatuts");
    }
#endif
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: CancelAsBundle_00002
 * @tc.desc: Test CancelAsBundle parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, CancelAsBundle_00002, Function | SmallTest | Level1)
{
    NotificationBundleOption bundleOption;
    int32_t notificationId = 10;
    bundleOption.SetBundleName("bundlename");
    bundleOption.SetUid(20);
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.CancelAsBundle(bundleOption, notificationId);
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_NE(ret, (int)ERR_ANS_NON_SYSTEM_APP);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    sptr<IRemoteObject> callerToken = nullptr;
    sptr<AnsDialogHostClient> client = nullptr;
    AnsDialogHostClient::CreateIfNullptr(client);
    client = AnsDialogHostClient::GetInstance();
    ErrCode ret = notificationHelper.RequestEnableNotification(deviceId, client, callerToken);
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
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
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
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
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
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
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_NE(ret, (int)ERR_ANS_NON_SYSTEM_APP);
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
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
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
    notificationHelper.EnableDistributed(enabled);
    EXPECT_EQ(enabled, true);
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
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
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
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
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
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
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
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
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
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
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
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
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
    EXPECT_NE(ret, (int)ERR_ANS_INVALID_BUNDLE);
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
    EXPECT_NE(ret, (int)ERR_ANS_NON_SYSTEM_APP);
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
    ErrCode ret = notificationHelper.SetEnabledForBundleSlot(bundleOption, slotType, enabled, false);
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
    notificationHelper.SetSyncNotificationEnabledWithoutApp(userId, enabled);
    EXPECT_EQ(enabled, true);
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
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: SetType_00001
 * @tc.desc: Test SetType_00001 parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, SetType_00001, Function | SmallTest | Level1)
{
    NotificationConstant::SlotType slotType = NotificationConstant::SlotType::SOCIAL_COMMUNICATION;
    auto slot1 = std::make_shared<NotificationSlot>(slotType);
    EXPECT_NE(slot1, nullptr);

    slotType = NotificationConstant::SlotType::SERVICE_REMINDER;
    auto slot2 = std::make_shared<NotificationSlot>(slotType);
    EXPECT_NE(slot2, nullptr);

    slotType = NotificationConstant::SlotType::CONTENT_INFORMATION;
    auto slot3 = std::make_shared<NotificationSlot>(slotType);
    EXPECT_NE(slot3, nullptr);

    slotType = NotificationConstant::SlotType::OTHER;
    auto slot4 = std::make_shared<NotificationSlot>(slotType);
    EXPECT_NE(slot4, nullptr);
}

/**
 * @tc.name: GetAllNotificationEnabledBundles_00001
 * @tc.desc: Test GetAllNotificationEnabledBundles parameters.
 * @tc.type: FUNC
 * @tc.require: issueI92VGR
 */
HWTEST_F(NotificationHelperTest, GetAllNotificationEnabledBundles_00001, Function | SmallTest | Level1)
{
    std::vector<NotificationBundleOption> bundleOption;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetAllNotificationEnabledBundles(bundleOption);
    EXPECT_EQ(ret, (int)ERR_ANS_NON_SYSTEM_APP);
}

/**
 * @tc.name: GetActiveNotificationByFilter_00001
 * @tc.desc: Test GetActiveNotificationByFilter parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, GetActiveNotificationByFilter_00001, Function | SmallTest | Level1)
{
    LiveViewFilter filter;
    sptr<NotificationRequest> request;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetActiveNotificationByFilter(filter, request);
    EXPECT_EQ(ret, (int)ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetSmartReminderEnabled_0100
 * @tc.desc: test SetSmartReminderEnabled with parameters
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, SetSmartReminderEnabled_0100, TestSize.Level1)
{
    std::string deviceType = "testDeviceType";
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetSmartReminderEnabled(deviceType, true);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: SetSmartReminderEnabled_0200
 * @tc.desc: test SetSmartReminderEnabled with parameters, expect errorCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, SetSmartReminderEnabled_0200, TestSize.Level1)
{
    std::string deviceType = "";
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetSmartReminderEnabled(deviceType, true);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: IsSmartReminderEnabled_0100
 * @tc.desc: test IsSmartReminderEnabled with parameters
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, IsSmartReminderEnabled_0100, TestSize.Level1)
{
    std::string deviceType = "testDeviceType1111";
    NotificationHelper notificationHelper;
    bool enable = true;
    ErrCode ret = notificationHelper.IsSmartReminderEnabled(deviceType, enable);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: SetBadgeNumberByBundle_0100
 * @tc.desc: test SetBadgeNumberByBundle with invalid bundleOption, expect errorCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, SetBadgeNumberByBundle_0100, TestSize.Level1)
{
    NotificationBundleOption bundleOption;
    int32_t badgeNumber = 0;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetBadgeNumberByBundle(bundleOption, badgeNumber);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: SetBadgeNumberByBundle_0200
 * @tc.desc: test SetBadgeNumberByBundle with invalid bundle name, expect errorCode ERR_ANS_INVALID_BUNDLE.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, SetBadgeNumberByBundle_0200, TestSize.Level1)
{
    NotificationBundleOption bundleOption;
    std::string bundleName = "bundleName";
    bundleOption.SetBundleName(bundleName);
    int32_t badgeNumber = 0;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetBadgeNumberByBundle(bundleOption, badgeNumber);
    EXPECT_EQ(ret, ERR_ANS_INVALID_BUNDLE);
}

/**
 * @tc.name: SetDistributedEnabledByBundle_0100
 * @tc.desc: test SetDistributedEnabledByBundle with parameters
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, SetDistributedEnabledByBundle_0100, TestSize.Level1)
{
    NotificationBundleOption bundleOption;
    std::string bundleName = "bundleName";
    bundleOption.SetBundleName(bundleName);
    bundleOption.SetUid(1);
    std::string deviceType = "testDeviceType";
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetDistributedEnabledByBundle(bundleOption, deviceType, true);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: SetDistributedEnabledByBundle_0200
 * @tc.desc: test SetDistributedEnabledByBundle with parameters, expect errorCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, SetDistributedEnabledByBundle_0200, TestSize.Level1)
{
    NotificationBundleOption bundleOption;
    std::string deviceType = "testDeviceType";
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetDistributedEnabledByBundle(bundleOption, deviceType, true);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: IsDistributedEnabledByBundle_0100
 * @tc.desc: test IsDistributedEnabledByBundle with parameters
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, IsDistributedEnabledByBundle_0100, TestSize.Level1)
{
    NotificationBundleOption bundleOption;
    std::string bundleName = "bundleName";
    bundleOption.SetBundleName(bundleName);
    bundleOption.SetUid(1);
    std::string deviceType = "testDeviceType1111";
    NotificationHelper notificationHelper;
    bool enable = true;
    ErrCode ret = notificationHelper.IsDistributedEnabledByBundle(bundleOption, deviceType, enable);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: IsDistributedEnabledByBundle_0200
 * @tc.desc: test IsDistributedEnabledByBundle with parameters, expect errorCode ERR_ANS_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, IsDistributedEnabledByBundle_0200, TestSize.Level1)
{
    NotificationBundleOption bundleOption;
    bundleOption.SetBundleName("");
    bundleOption.SetUid(1);
    std::string deviceType = "testDeviceType";
    NotificationHelper notificationHelper;
    bool enable = true;
    ErrCode ret = notificationHelper.IsDistributedEnabledByBundle(bundleOption, deviceType, enable);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: AddDoNotDisturbProfiles_0100
 * @tc.desc: test AddDoNotDisturbProfiles when profiles is empty.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, AddDoNotDisturbProfiles_0100, TestSize.Level1)
{
    NotificationHelper notificationHelper;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    profiles.clear();
    ErrCode ret = notificationHelper.AddDoNotDisturbProfiles(profiles);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, ret);
}

/**
 * @tc.name: RemoveDoNotDisturbProfiles_0100
 * @tc.desc: test RemoveDoNotDisturbProfiles when profiles is empty.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, RemoveDoNotDisturbProfiles_0100, TestSize.Level1)
{
    NotificationHelper notificationHelper;
    std::vector<sptr<NotificationDoNotDisturbProfile>> profiles;
    profiles.clear();
    ErrCode ret = notificationHelper.RemoveDoNotDisturbProfiles(profiles);
    EXPECT_EQ(ERR_ANS_INVALID_PARAM, ret);
}

/**
 * @tc.name: SetTargetDeviceStatus_0100
 * @tc.desc: test SetTargetDeviceStatus with parameters
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, SetTargetDeviceStatus_0100, TestSize.Level1)
{
    std::string deviceType = "testDeviceType";
    int32_t status = 1;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.SetTargetDeviceStatus(deviceType, status);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: RegisterSwingCallback_0100
 * @tc.desc: test RegisterSwingCallback with parameters
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, RegisterSwingCallback_0100, TestSize.Level1)
{
#ifdef NOTIFICATION_SMART_REMINDER_SUPPORTED
    std::function<void(bool, int)> swingCbFunc =
        std::bind(&NotificationHelperTest::UpdateStatuts, this, std::placeholders::_1, std::placeholders::_2);
    EXPECT_TRUE(swingCbFunc);
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.RegisterSwingCallback(swingCbFunc);
    EXPECT_EQ(ret, ERR_OK);
#endif
}

/**
 * @tc.name: IsNeedSilentInDoNotDisturbMode_00001
 * @tc.desc: Test IsNeedSilentInDoNotDisturbMode parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(NotificationHelperTest, IsNeedSilentInDoNotDisturbMode_00001, Function | SmallTest | Level1)
{
    std::string phoneNumber = "11111111111";
    int32_t callerType = 0;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.IsNeedSilentInDoNotDisturbMode(phoneNumber, callerType);
    EXPECT_EQ(ret, (int)ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: UpdateNotificationTimerByUid_00001
 * @tc.desc: Test UpdateNotificationTimerByUid.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, UpdateNotificationTimerByUid_00001, Function | SmallTest | Level1)
{
    int32_t uid = 20099999;
    bool isPaused = true;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.UpdateNotificationTimerByUid(uid, isPaused);
    EXPECT_EQ(ret, (int)ERR_OK);
}

/**
 * @tc.name: DisableNotificationFeature_00001
 * @tc.desc: Test DisableNotificationFeature.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, DisableNotificationFeature_00001, Function | SmallTest | Level1)
{
    NotificationDisable notificationDisable;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.DisableNotificationFeature(notificationDisable);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: SilentReminderEnabled_00001
 * @tc.desc: Test SetSilentReminderEnabled.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, SetSilentReminderEnabled_00001, Function | SmallTest | Level1)
{
    NotificationHelper notificationHelper;
    NotificationBundleOption bo;
    bo.SetBundleName("bundleName");
    bo.SetUid(1);
    ErrCode ret = notificationHelper.SetSilentReminderEnabled(bo, true);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}

/**
 * @tc.name: SilentReminderEnabled_00002
 * @tc.desc: Test SetSilentReminderEnabled.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, SetSilentReminderEnabled_00002, Function | SmallTest | Level1)
{
    NotificationHelper notificationHelper;
    NotificationBundleOption bo;
    bo.SetUid(1);
    ErrCode ret = notificationHelper.SetSilentReminderEnabled(bo, true);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: IsSilentReminderEnabled_00001
 * @tc.desc: Test SetSilentReminderEnabled.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, IsSilentReminderEnabled_00001, Function | SmallTest | Level1)
{
    NotificationHelper notificationHelper;
    NotificationBundleOption bo;
    bo.SetUid(1);
    int32_t enableStatus = 0;
    ErrCode ret = notificationHelper.IsSilentReminderEnabled(bo, enableStatus);
    EXPECT_EQ(ret, ERR_ANS_INVALID_PARAM);
}

/**
 * @tc.name: GetDistributedDevicelist_0100
 * @tc.desc: Test GetDistributedDevicelist.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationHelperTest, GetDistributedDevicelist_0100, Function | SmallTest | Level1)
{
    std::vector<std::string> deviceTypes;
    NotificationHelper notificationHelper;
    ErrCode ret = notificationHelper.GetDistributedDevicelist(deviceTypes);
    EXPECT_EQ(ret, ERR_ANS_PERMISSION_DENIED);
}
}
}
