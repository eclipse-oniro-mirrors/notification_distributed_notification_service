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

#include "ans_inner_errors.h"
#include "ans_log_wrapper.h"
#include "distributed_data_define.h"
#include "distributed_bundle_service.h"
#include "mock_bundle_manager_helper.h"

namespace OHOS {
namespace Notification {

using namespace testing::ext;

class DistributedBundleServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() {};
    void TearDown() {};
};

void DistributedBundleServiceTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "SetUp Case start";
    MockBundleManager::MockClearInstalledBundle();
    MockBundleManager::MockBundleInterfaceResult(0);
    GTEST_LOG_(INFO) << "SetUp end";
}

void DistributedBundleServiceTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "TearDown case";
}


void MockInstalledBundle()
{
    NotificationBundleOption bundleOption0 = NotificationBundleOption("com.test.demo10", 20002010);
    bundleOption0.SetAppName("demo10");
    NotificationBundleOption bundleOption1 = NotificationBundleOption("com.test.demo3", 20002001);
    bundleOption1.SetAppName("demo");
    NotificationBundleOption bundleOption2 = NotificationBundleOption("com.test.demo", 20002002);
    bundleOption2.SetAppName("demo4");
    NotificationBundleOption bundleOption3 = NotificationBundleOption("com.test.demo5", 20002003);
    bundleOption3.SetAppName("demo5");
    MockBundleManager::MockInstallBundle(bundleOption0);
    MockBundleManager::MockInstallBundle(bundleOption1);
    MockBundleManager::MockInstallBundle(bundleOption2);
    MockBundleManager::MockInstallBundle(bundleOption3);
}

/**
 * @tc.name: Distributed bundle list check
 * @tc.desc: Test device bundle service
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedBundleServiceTest, DistributedBundleList_00001, Function | SmallTest | Level1)
{
    // device connect
    DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::INIT_DEVICE_CONNECT, {});
    ASSERT_EQ(DistributedBundleService::GetInstance().connected.load(), true);

    // master add bundle
    std::vector<NotificationDistributedBundle> bundles;
    NotificationDistributedBundle bundle1 = NotificationDistributedBundle("com.test.demo1", 20002001);
    bundle1.SetBundleLabel("demo1");
    bundles.push_back(bundle1);
    NotificationDistributedBundle bundle2 = NotificationDistributedBundle("com.test.demo2", 20002002);
    bundles.push_back(bundle2);
    NotificationDistributedBundle bundle3 = NotificationDistributedBundle();
    bundle3.SetBundleUid(20002003);
    bundle3.SetBundleLabel("demo3");
    bundles.push_back(bundle3);
    NotificationDistributedBundle bundle4 = NotificationDistributedBundle("com.test.demo4", 20002004);
    bundle4.SetBundleLabel("demo4");
    bundles.push_back(bundle4);
    NotificationDistributedBundle bundle5 = NotificationDistributedBundle("com.test.demo5", 20002005);
    bundle4.SetBundleLabel("demo5");
    bundles.push_back(bundle5);

    MockInstalledBundle();
    MockBundleManager::MockBundleInterfaceResult(-1);
    auto result = DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::MASTER_BUNDLE_ADD, bundles);
    ASSERT_EQ(result, static_cast<int32_t>(ERR_ANS_TASK_ERR));
    MockBundleManager::MockBundleInterfaceResult(0);
    result = DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::MASTER_BUNDLE_ADD, bundles);
    ASSERT_EQ(result, static_cast<int32_t>(ERR_OK));
    ASSERT_EQ(DistributedBundleService::GetInstance().bundleList_.size(), bundles.size());

    DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::MASTER_BUNDLE_REMOVE, { bundle2 });
    ASSERT_EQ(DistributedBundleService::GetInstance().bundleList_.size(), 4);

    // device disconnect
    DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::END_DEVICE_CONNECT, {});
    ASSERT_EQ(DistributedBundleService::GetInstance().connected.load(), false);
}

/**
 * @tc.name: Distributed bundle list check
 * @tc.desc: Test device bundle service
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedBundleServiceTest, DistributedBundleList_00002, Function | SmallTest | Level1)
{
    // device connect
    DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::INIT_DEVICE_CONNECT, {});
    ASSERT_EQ(DistributedBundleService::GetInstance().connected.load(), true);

    // master add bundle
    std::vector<NotificationDistributedBundle> bundles;
    NotificationDistributedBundle bundle1 = NotificationDistributedBundle("com.test.demo1", 20002001);
    bundle1.SetBundleLabel("demo1");
    bundles.push_back(bundle1);
    NotificationDistributedBundle bundle2 = NotificationDistributedBundle("com.test.demo2", 20002002);
    bundle1.SetBundleLabel("demo2");
    bundles.push_back(bundle2);
    auto result = DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::MASTER_BUNDLE_ADD, bundles);
    ASSERT_EQ(result, static_cast<int32_t>(ERR_OK));

    NotificationDistributedBundle changeBundle = NotificationDistributedBundle("com.test.demo1", 20002001);
    MockBundleManager::MockBundleInterfaceResult(-1);
    result = DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::MASTER_NOTIFICATION_ENABLE, { changeBundle });
    ASSERT_EQ(result, static_cast<int32_t>(ERR_ANS_TASK_ERR));
    MockBundleManager::MockBundleInterfaceResult(0);
    result = DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::MASTER_LIVEVIEW_ENABLE, { changeBundle });
    ASSERT_EQ(result, static_cast<int32_t>(ERR_OK));
    result = DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::MASTER_NOTIFICATION_ENABLE, { changeBundle });
    ASSERT_EQ(result, static_cast<int32_t>(ERR_OK));

    MockInstalledBundle();
    NotificationDistributedBundle changeBundle1 = NotificationDistributedBundle("com.test.demo3", 20002003);
    changeBundle1.SetBundleLabel("demo3");
    result = DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::MASTER_LIVEVIEW_ENABLE, { changeBundle1 });
    ASSERT_EQ(result, static_cast<int32_t>(ERR_OK));

    NotificationDistributedBundle changeBundle2 = NotificationDistributedBundle("com.test.demo4", 20002003);
    changeBundle1.SetBundleLabel("demo4");
    result = DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::MASTER_NOTIFICATION_ENABLE, { changeBundle2 });
    ASSERT_EQ(result, static_cast<int32_t>(ERR_OK));
    // check device
    NotificationDistributedBundle changeBundle3 = NotificationDistributedBundle("com.test.demo5", 20002003);
    changeBundle3.SetBundleLabel("demo5");
    result = DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::MASTER_NOTIFICATION_ENABLE, { changeBundle3 });
    ASSERT_EQ(result, static_cast<int32_t>(ERR_OK));

    // device disconnect
    DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::END_DEVICE_CONNECT, {});
    ASSERT_EQ(DistributedBundleService::GetInstance().connected.load(), false);
}

/**
 * @tc.name: Distributed bundle list check
 * @tc.desc: Test device bundle service
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedBundleServiceTest, DistributedBundleList_00003, Function | SmallTest | Level1)
{
    // device connect
    DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::INIT_DEVICE_CONNECT, {});
    ASSERT_EQ(DistributedBundleService::GetInstance().connected.load(), true);

    // master add bundle
    std::vector<NotificationDistributedBundle> bundles;
    NotificationDistributedBundle bundle1 = NotificationDistributedBundle("com.test.demo1", 20002001);
    bundle1.SetBundleLabel("demo1");
    bundles.push_back(bundle1);
    NotificationDistributedBundle bundle2 = NotificationDistributedBundle("com.test.demo2", 20002002);
    bundle1.SetBundleLabel("demo2");
    bundles.push_back(bundle2);
    auto result = DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::MASTER_BUNDLE_ADD, bundles);
    ASSERT_EQ(result, static_cast<int32_t>(ERR_OK));

    // slave add bundle
    sptr<NotificationBundleOption> option0 = new NotificationBundleOption("com.test.demo0", 20002000);
    option0->SetAppName("demo0");
    DistributedBundleService::GetInstance().HandleSlaveBundleChange(
        DistributedBundleChangeType::SLAVE_BUNDLE_ADD, option0);
    
    sptr<NotificationBundleOption> option1 = new NotificationBundleOption("com.test.demo1", 20002001);
    option1->SetAppName("demo1");
    DistributedBundleService::GetInstance().HandleSlaveBundleChange(
        DistributedBundleChangeType::SLAVE_BUNDLE_ADD, option1);
    DistributedBundleService::GetInstance().HandleSlaveBundleChange(
        DistributedBundleChangeType::SLAVE_BUNDLE_REMOVE, option1);
    DistributedBundleService::GetInstance().HandleSlaveBundleChange(
        DistributedBundleChangeType::SLAVE_BUNDLE_REMOVE, option1);

    // device disconnect
    DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::END_DEVICE_CONNECT, {});
    ASSERT_EQ(DistributedBundleService::GetInstance().connected.load(), false);
}

/**
 * @tc.name: Distributed bundle list check
 * @tc.desc: Test device bundle service
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(DistributedBundleServiceTest, DistributedBundleList_00004, Function | SmallTest | Level1)
{
    // device connect
    DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::INIT_DEVICE_CONNECT, {});
    ASSERT_EQ(DistributedBundleService::GetInstance().connected.load(), true);

    // master add bundle
    std::vector<NotificationDistributedBundle> bundles;
    NotificationDistributedBundle bundle1 = NotificationDistributedBundle("com.test.demo1", 20002001);
    bundle1.SetBundleLabel("demo1");
    bundles.push_back(bundle1);
    NotificationDistributedBundle bundle2 = NotificationDistributedBundle("com.test.demo2", 20002002);
    bundle1.SetBundleLabel("demo2");
    bundles.push_back(bundle2);
    auto result = DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::MASTER_BUNDLE_ADD, bundles);
    ASSERT_EQ(result, static_cast<int32_t>(ERR_OK));

    // slave add bundle
    NotificationDistributedBundle changeBundle0 = NotificationDistributedBundle("com.test.demo0", 20002000);
    changeBundle0.SetBundleLabel("demo0");
    result = DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::COLLABORATION_LIVEVIEW_ENABLE, { changeBundle0 });
    ASSERT_EQ(result, static_cast<int32_t>(ERR_ANS_INVALID_PARAM));
    
    NotificationDistributedBundle changeBundle1 = NotificationDistributedBundle("com.test.demo1", 20002001);
    changeBundle0.SetBundleLabel("demo1");
    result = DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::COLLABORATION_LIVEVIEW_ENABLE, { changeBundle1 });
    ASSERT_EQ(result, static_cast<int32_t>(ERR_OK));

    result = DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::COLLABORATION_NOTIFICATION_ENABLE, { changeBundle1 });
    ASSERT_EQ(result, static_cast<int32_t>(ERR_OK));

    DistributedBundleService::GetInstance().PublishDistributedStateChange(
        static_cast<DistributedEventType>(-1), nullptr);
    DistributedBundleService::GetInstance().PublishDistributedStateChange(
        static_cast<DistributedEventType>(100), nullptr);
    DistributedBundleService::GetInstance().PublishDistributedStateChange(
        DistributedEventType::CLEAR_DISTRIBUTED_BUNDLES, nullptr);
    DistributedBundleService::GetInstance().PublishDistributedStateChange(
        DistributedEventType::UPDATE_DISTRIBUTED_BUNDLE, nullptr);

    DistributedBundleService::GetInstance().HandleLocalSwitchEvent(
        DistributedBundleChangeType::COLLABORATION_NOTIFICATION_ENABLE, "com.test.demo1", 20002001, false);
    // device disconnect
    DistributedBundleService::GetInstance().SetDeviceDistributedBundleList(
        DistributedBundleChangeType::END_DEVICE_CONNECT, {});
    ASSERT_EQ(DistributedBundleService::GetInstance().connected.load(), false);
}
}
}
