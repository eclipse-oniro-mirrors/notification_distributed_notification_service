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

#define private public
#define protected public
#include "notification_application_change_info.h"
#include "notification_distributed_bundle.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class ApplicationChangeInfoTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: ApplicationChangeInfoTest_00001
 * @tc.desc: Test interface parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationChangeInfoTest, ApplicationChangeInfoTest_00001, Function | SmallTest | Level1)
{
    auto changeInfo = std::make_shared<NotificationApplicationChangeInfo>();
    changeInfo->SetChangeType(DistributedBundleChangeType::MASTER_BUNDLE_ADD);
    EXPECT_EQ(changeInfo->GetChangeType(), DistributedBundleChangeType::MASTER_BUNDLE_ADD);

    auto bundle = std::make_shared<NotificationBundleOption>("com.test.demo", 20020001);
    changeInfo->SetBundle(bundle);
    EXPECT_NE(changeInfo->GetBundle(), nullptr);

    changeInfo->SetEnable(true);
    EXPECT_EQ(changeInfo->GetEnable(), true);
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ApplicationChangeInfoTest, Marshalling_00001, Function | SmallTest | Level1)
{
    auto changeInfo = std::make_shared<NotificationApplicationChangeInfo>();
    changeInfo->SetChangeType(DistributedBundleChangeType::MASTER_BUNDLE_ADD);
    auto bundle = std::make_shared<NotificationBundleOption>("com.test.demo", 20020001);
    changeInfo->SetBundle(bundle);

    Parcel parcel;
    EXPECT_EQ(changeInfo->Marshalling(parcel), true);

    auto changeInfoPoint = NotificationApplicationChangeInfo::Unmarshalling(parcel);
    EXPECT_NE(changeInfoPoint, nullptr);
    delete changeInfoPoint;
}

/**
 * @tc.name: BundleMarshalling_00001
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(ApplicationChangeInfoTest, BundleMarshalling_00001, Function | SmallTest | Level1)
{
    auto distributedBundle = std::make_shared<NotificationDistributedBundle>();
    distributedBundle->SetAncoBundle(true);
    distributedBundle->SetBundleName("com.test.demo");
    EXPECT_EQ(distributedBundle->IsAncoBundle(), true);
    EXPECT_EQ(distributedBundle->GetBundleIcon(), nullptr);
    EXPECT_EQ(distributedBundle->GetBundleName(), "com.test.demo");
    Parcel parcel;
    EXPECT_EQ(distributedBundle->Marshalling(parcel), true);

    auto distributedBundlePoint = NotificationDistributedBundle::Unmarshalling(parcel);
    EXPECT_NE(distributedBundlePoint, nullptr);
    delete distributedBundlePoint;
}

/**
 * @tc.name: BundleMarshalling_00002
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(ApplicationChangeInfoTest, BundleMarshalling_00002, Function | SmallTest | Level1)
{
    auto distributedBundle = std::make_shared<NotificationDistributedBundle>();
    distributedBundle->SetAncoBundle(true);
    distributedBundle->SetBundleName("com.test.demo");
    distributedBundle->SetBundleIcon(std::make_shared<Media::PixelMap>());
    Parcel parcel;
    EXPECT_EQ(distributedBundle->Marshalling(parcel), false);

    auto distributedBundlePoint = NotificationDistributedBundle::Unmarshalling(parcel);
    EXPECT_EQ(distributedBundlePoint, nullptr);
}

/**
 * @tc.name: BundleMarshalling_00002
 * @tc.desc: Test Marshalling parameters.
 * @tc.type: FUNC
 * @tc.require: issueI5WBBH
 */
HWTEST_F(ApplicationChangeInfoTest, BundleMarshalling_00003, Function | SmallTest | Level1)
{
    auto distributedBundle = std::make_shared<NotificationDistributedBundle>();
    distributedBundle->SetInstalledbundle("", "");
    EXPECT_EQ(distributedBundle->existSame_, false);
    EXPECT_EQ(distributedBundle->CheckInstalledBundle("", ""), false);
    EXPECT_EQ(distributedBundle->CheckInstalledBundle("name", "label"), false);

    distributedBundle->SetInstalledbundle("name", "");
    EXPECT_EQ(distributedBundle->existSame_, true);
    EXPECT_EQ(distributedBundle->CheckInstalledBundle("", ""), false);
    EXPECT_EQ(distributedBundle->CheckInstalledBundle("name", ""), true);

    distributedBundle->SetInstalledbundle("", "label");
    EXPECT_EQ(distributedBundle->existSame_, true);
    EXPECT_EQ(distributedBundle->CheckInstalledBundle("", ""), false);
    EXPECT_EQ(distributedBundle->CheckInstalledBundle("", "label"), true);

    distributedBundle->SetInstalledbundle("name", "label");
    EXPECT_EQ(distributedBundle->existSame_, true);
}
} // namespace Notification
} // namespace OHOS
