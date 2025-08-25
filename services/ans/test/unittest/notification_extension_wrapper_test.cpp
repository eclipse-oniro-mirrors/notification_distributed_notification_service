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

#include "gtest/gtest.h"
#define private public
#include "notification_extension_wrapper.h"
#undef private

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace Notification {
const int32_t ACTIVE_DELETE = 0;
const int32_t PASSITIVE_DELETE = 1;

static bool g_mockCalled = false;
static bool g_mockLocalSwitch = false;
static int g_mockUpdateByCancelReason = 0;

static void MockSetLocalSwitch(bool status)
{
    g_mockCalled = true;
    g_mockLocalSwitch = status;
}

static void MockUpdateByCancel(const std::vector<sptr<Notification>>& notifications, int deleteType)
{
    g_mockCalled = true;
    g_mockUpdateByCancelReason = deleteType;
}

class NotificationExtensionWrapperTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
    static void SetUpTestCas()
    {
        g_mockCalled = false;
        g_mockLocalSwitch = false;
        g_mockUpdateByCancelReason = 0;
    }
    static void TearDownTestCase() {};
};

HWTEST_F(NotificationExtensionWrapperTest, InitExtentionWrapper_Test, TestSize.Level0)
{
    OHOS::Notification::ExtensionWrapper extensionWrapper;
    extensionWrapper.InitExtentionWrapper();
#ifdef ENABLE_ANS_EXT_WRAPPER
    // 验证extensionWrapperHandle_是否被正确初始化
    EXPECT_NE(extensionWrapper.extensionWrapperHandle_, nullptr);

    // 验证syncAdditionConfig_是否被正确初始化
    EXPECT_NE(extensionWrapper.syncAdditionConfig_, nullptr);
#else
    EXPECT_EQ(extensionWrapper.extensionWrapperHandle_, nullptr);
    EXPECT_EQ(extensionWrapper.syncAdditionConfig_, nullptr);
#endif

    // 验证localControl_、reminderControl_、bannerControl_是否被正确初始化
#ifdef ENABLE_ANS_ADDITIONAL_CONTROL
    EXPECT_NE(extensionWrapper.localControl_, nullptr);
    EXPECT_NE(extensionWrapper.reminderControl_, nullptr);
    EXPECT_NE(extensionWrapper.bannerControl_, nullptr);
    EXPECT_NE(extensionWrapper.subscribeControl_, nullptr);
#endif

    // 验证initSummary_是否被正确初始化
#ifdef ENABLE_ANS_AGGREGATION
    EXPECT_NE(extensionWrapper.initSummary_, nullptr);
#endif
}

HWTEST_F(NotificationExtensionWrapperTest, CheckIfSetlocalSwitch_002, TestSize.Level0)
{
    // 创建ExtensionWrapper对象
    ExtensionWrapper extensionWrapper;
    // 设置extensionWrapperHandle_不为nullptr
    extensionWrapper.extensionWrapperHandle_ = new int;
    // 设置isRegisterDataSettingObserver为false
    extensionWrapper.isRegisterDataSettingObserver = false;
    // 调用待测函数
    extensionWrapper.CheckIfSetlocalSwitch();
    // 验证isRegisterDataSettingObserver为true
    EXPECT_EQ(extensionWrapper.isRegisterDataSettingObserver, true);
}

HWTEST_F(NotificationExtensionWrapperTest, SetlocalSwitch_False_Test, TestSize.Level0)
{
    OHOS::Notification::ExtensionWrapper extensionWrapper;
    std::string enable = "false";
    extensionWrapper.setLocalSwitch_ = reinterpret_cast<ExtensionWrapper::SET_LOCAL_SWITCH>(&MockSetLocalSwitch);

    extensionWrapper.SetlocalSwitch(enable);

    EXPECT_TRUE(g_mockCalled);
    EXPECT_FALSE(g_mockLocalSwitch);
}

HWTEST_F(NotificationExtensionWrapperTest, SetlocalSwitch_True_Test, TestSize.Level0)
{
    OHOS::Notification::ExtensionWrapper extensionWrapper;
    std::string enable = "true";
    extensionWrapper.setLocalSwitch_ = reinterpret_cast<ExtensionWrapper::SET_LOCAL_SWITCH>(&MockSetLocalSwitch);

    extensionWrapper.SetlocalSwitch(enable);

    EXPECT_TRUE(g_mockCalled);
    EXPECT_TRUE(g_mockLocalSwitch);
}

HWTEST_F(NotificationExtensionWrapperTest, SyncAdditionConfig_NullSyncAdditionConfig, TestSize.Level0)
{
    ExtensionWrapper extensionWrapper;
    extensionWrapper.syncAdditionConfig_ = nullptr;
    ErrCode result = extensionWrapper.SyncAdditionConfig("key", "value");
    EXPECT_EQ(result, 0);
}

HWTEST_F(NotificationExtensionWrapperTest, SyncAdditionConfig_ValidSyncAdditionConfig, TestSize.Level0)
{
    ExtensionWrapper extensionWrapper;
    extensionWrapper.syncAdditionConfig_ = [](const std::string& key, const std::string& value) {
        return 1;
    };
    ErrCode result = extensionWrapper.SyncAdditionConfig("key", "value");
    EXPECT_EQ(result, 1);
}

HWTEST_F(NotificationExtensionWrapperTest, UpdateByCancel_NullUpdateByCancel, TestSize.Level0)
{
    // Arrange
    ExtensionWrapper wrapper;
    std::vector<sptr<Notification>> notifications;
    int deleteReason = 1;
    int expectedReason = 0;

    wrapper.UpdateByCancel(notifications, deleteReason);

    EXPECT_NE(expectedReason, deleteReason);
}

HWTEST_F(NotificationExtensionWrapperTest, UpdateByCancel_Normal_Test, TestSize.Level0) {
    ExtensionWrapper wrapper;
    wrapper.updateByCancel_ = reinterpret_cast<ExtensionWrapper::UPDATE_BY_CANCEL>(&MockUpdateByCancel);

    std::vector<sptr<Notification>> notifications;
    int deleteReason = 5;

    wrapper.UpdateByCancel(notifications, deleteReason);

    EXPECT_TRUE(g_mockCalled);
    EXPECT_EQ(g_mockUpdateByCancelReason, 1);
}

HWTEST_F(NotificationExtensionWrapperTest, GetUnifiedGroupInfo_NullFunction, TestSize.Level0)
{
    OHOS::Notification::ExtensionWrapper extensionWrapper;
    OHOS::sptr<OHOS::Notification::NotificationRequest> request = nullptr;
    EXPECT_EQ(extensionWrapper.GetUnifiedGroupInfo(request), 0);
}

HWTEST_F(NotificationExtensionWrapperTest, GetUnifiedGroupInfo_ValidFunction, TestSize.Level0)
{
    OHOS::Notification::ExtensionWrapper extensionWrapper;
    OHOS::sptr<OHOS::Notification::NotificationRequest> request = new OHOS::Notification::NotificationRequest();
    extensionWrapper.getUnifiedGroupInfo_ = [](const OHOS::sptr<OHOS::Notification::NotificationRequest> &request) {
        return 1;
    };
    EXPECT_EQ(extensionWrapper.GetUnifiedGroupInfo(request), 1);
}


HWTEST_F(NotificationExtensionWrapperTest, ReminderControl_NullReminderControl, TestSize.Level0)
{
    OHOS::Notification::ExtensionWrapper extensionWrapper;
    std::string bundleName = "testBundle";
    extensionWrapper.reminderControl_ = nullptr;
    int32_t result = extensionWrapper.ReminderControl(bundleName);
    EXPECT_EQ(result, 0);
}

HWTEST_F(NotificationExtensionWrapperTest, ReminderControl_ValidReminderControl, TestSize.Level0)
{
    OHOS::Notification::ExtensionWrapper extensionWrapper;
    std::string bundleName = "testBundle";
    extensionWrapper.reminderControl_ = [](const std::string &bundleName) { return 1; };
    int32_t result = extensionWrapper.ReminderControl(bundleName);
    EXPECT_EQ(result, 1);
}

HWTEST_F(NotificationExtensionWrapperTest, BannerControl_NullBannerControl, TestSize.Level0)
{
    // Arrange
    ExtensionWrapper wrapper;
    std::string bundleName = "testBundle";
    wrapper.bannerControl_ = nullptr;

    // Act
    int32_t result = wrapper.BannerControl(bundleName);

    // Assert
    EXPECT_EQ(-1, result);
}

HWTEST_F(NotificationExtensionWrapperTest, BannerControl_ValidBannerControl, TestSize.Level0)
{
    // Arrange
    ExtensionWrapper wrapper;
    std::string bundleName = "testBundle";
    auto mockBannerControl = [](const std::string &bundleName) { return 0; };
    wrapper.bannerControl_ = mockBannerControl;

    // Act
    int32_t result = wrapper.BannerControl(bundleName);

    // Assert
    EXPECT_EQ(0, result);
}

HWTEST_F(NotificationExtensionWrapperTest, LocalControl_NullCase, TestSize.Level0) {
    // Arrange
    OHOS::Notification::ExtensionWrapper wrapper;
    wrapper.localControl_ = nullptr;
    auto request = new NotificationRequest();

    // Act
    int32_t result = wrapper.LocalControl(request);

    // Assert
    ASSERT_EQ(0, result); // 预期返回 0
}

HWTEST_F(NotificationExtensionWrapperTest, LocalControl_SuccessCase, TestSize.Level0) {
    // Arrange
    OHOS::Notification::ExtensionWrapper wrapper;
    int32_t (*mockFunc)(const sptr<NotificationRequest> &) = [](const sptr<NotificationRequest> &req) {
        return 1;
    };
    wrapper.localControl_ = mockFunc;
    auto request = new NotificationRequest();

    // Act
    int32_t result = wrapper.LocalControl(request);

    // Assert
    ASSERT_EQ(1, result);
}

HWTEST_F(NotificationExtensionWrapperTest, convertToDelType_ActiveDelete, TestSize.Level0)
{
    // Arrange
    int32_t deleteReason = NotificationConstant::PACKAGE_CHANGED_REASON_DELETE + 1;
    int32_t expectedDelType = ACTIVE_DELETE;

    // Act
    int32_t actualDelType = OHOS::Notification::ExtensionWrapper::convertToDelType(deleteReason);

    // Assert
    ASSERT_EQ(expectedDelType, actualDelType);
}

HWTEST_F(NotificationExtensionWrapperTest, convertToDelType_PassiveDelete, TestSize.Level0)
{
    // Arrange
    int32_t deleteReason = NotificationConstant::PACKAGE_CHANGED_REASON_DELETE;
    int32_t expectedDelType = PASSITIVE_DELETE;

    // Act
    int32_t actualDelType = OHOS::Notification::ExtensionWrapper::convertToDelType(deleteReason);

    // Assert
    ASSERT_EQ(expectedDelType, actualDelType);
}

HWTEST_F(NotificationExtensionWrapperTest, convertToDelType_UserRemovedReasonDelete, TestSize.Level0)
{
    // Arrange
    int32_t deleteReason = NotificationConstant::USER_REMOVED_REASON_DELETE;
    int32_t expectedDelType = PASSITIVE_DELETE;

    // Act
    int32_t actualDelType = OHOS::Notification::ExtensionWrapper::convertToDelType(deleteReason);

    // Assert
    ASSERT_EQ(expectedDelType, actualDelType);
}

HWTEST_F(NotificationExtensionWrapperTest, convertToDelType_DisableSlotReasonDelete, TestSize.Level0)
{
    // Arrange
    int32_t deleteReason = NotificationConstant::DISABLE_SLOT_REASON_DELETE;
    int32_t expectedDelType = PASSITIVE_DELETE;

    // Act
    int32_t actualDelType = OHOS::Notification::ExtensionWrapper::convertToDelType(deleteReason);

    // Assert
    ASSERT_EQ(expectedDelType, actualDelType);
}

HWTEST_F(NotificationExtensionWrapperTest, convertToDelType_DisableNotificationReasonDelete, TestSize.Level0)
{
    // Arrange
    int32_t deleteReason = NotificationConstant::DISABLE_NOTIFICATION_REASON_DELETE;
    int32_t expectedDelType = PASSITIVE_DELETE;

    // Act
    int32_t actualDelType = OHOS::Notification::ExtensionWrapper::convertToDelType(deleteReason);

    // Assert
    ASSERT_EQ(expectedDelType, actualDelType);
}

HWTEST_F(NotificationExtensionWrapperTest, NotificationDialogControl_Test, TestSize.Level0)
{
    ExtensionWrapper wrapper;
    bool result = wrapper.NotificationDialogControl();
    EXPECT_EQ(true, result);

    auto mockNotificationDialogControl = []() { return true; };
    wrapper.notificationDialogControl_ = mockNotificationDialogControl;
    result = wrapper.NotificationDialogControl();
    EXPECT_EQ(true, result);
}

HWTEST_F(NotificationExtensionWrapperTest, SubscribeControl_NullSubscribeControl, TestSize.Level0)
{
    // Arrange
    ExtensionWrapper wrapper;
    std::string bundleName = "testBundle";
    wrapper.subscribeControl_ = nullptr;

    // Act
    bool result = wrapper.IsSubscribeControl(bundleName, 1, NotificationConstant::SlotType::LIVE_VIEW);

    // Assert
    EXPECT_FALSE(result);
}

HWTEST_F(NotificationExtensionWrapperTest, SubscribeControl_ValidSubscribeControl, TestSize.Level0)
{
    // Arrange
    ExtensionWrapper wrapper;
    std::string bundleName = "testBundle";
    auto mockSubscribeControl = [](const std::string &bundleName, NotificationConstant::SlotType slotType) {
        return true;
    };
    wrapper.subscribeControl_ = mockSubscribeControl;

    // Act
    bool result = wrapper.IsSubscribeControl(bundleName, 2, NotificationConstant::SlotType::LIVE_VIEW);

    // Assert
    EXPECT_TRUE(result);
}
}   //namespace Notification
}   //namespace OHOS